from flask import Flask, jsonify, request, abort
from flask_cors import CORS
from functools import wraps
import psutil
import time
from collections import defaultdict
import datetime
import json
import os
import threading
import subprocess
import hashlib
import ipaddress
import secrets

app = Flask(__name__)
CORS(app)

class AuthManager:
    def __init__(self):
        self.config_file = 'auth_config.json'
        self.load_config()
        
    def load_config(self):
        if os.path.exists(self.config_file):
            with open(self.config_file, 'r') as f:
                self.config = json.load(f)
        else:
            # 默认配置
            self.config = {
                'password_hash': hashlib.sha256('admin'.encode()).hexdigest(),  # 默认密码
                'allowed_ips': ['127.0.0.1', '::1'],  # 默认允许本地访问
                'tokens': {}
            }
            self.save_config()
    
    def save_config(self):
        with open(self.config_file, 'w') as f:
            json.dump(self.config, f, indent=2)
    
    def check_ip(self, ip):
        """检查IP是否允许访问"""
        if not self.config['allowed_ips']:  # 如果允许IP列表为空，则允许所有IP
            return True
            
        client_ip = ipaddress.ip_address(ip)
        for allowed_ip in self.config['allowed_ips']:
            if '/' in allowed_ip:  # 处理CIDR格式
                if client_ip in ipaddress.ip_network(allowed_ip):
                    return True
            else:
                if client_ip == ipaddress.ip_address(allowed_ip):
                    return True
        return False
    
    def verify_password(self, password):
        """验证密码"""
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        return password_hash == self.config['password_hash']
    
    def generate_token(self):
        """生成新的访问令牌"""
        token = secrets.token_urlsafe(32)
        expires = datetime.datetime.now() + datetime.timedelta(hours=24)  # 24小时后过期
        self.config['tokens'][token] = expires.isoformat()
        self.save_config()
        return token
    
    def verify_token(self, token):
        """验证令牌是否有效"""
        if token not in self.config['tokens']:
            return False
        
        expires = datetime.datetime.fromisoformat(self.config['tokens'][token])
        if datetime.datetime.now() > expires:
            del self.config['tokens'][token]
            self.save_config()
            return False
            
        return True

class TrafficController:
    def __init__(self):
        self.rules = {}  # {(protocol, port): limit_bytes_per_sec}
        self.stats = defaultdict(lambda: {
            'current_speed': 0,
            'limit': 0,
            'status': 'Normal'
        })
        self.lock = threading.Lock()

    def add_rule(self, protocol, port, limit):
        """添加流量限制规则"""
        limit_bytes = self._parse_limit(limit)
        with self.lock:
            self.rules[(protocol, port)] = limit_bytes
            self._apply_tc_limit(protocol, port, limit_bytes)

    def remove_rule(self, protocol, port):
        """移除流量限制规则"""
        with self.lock:
            if (protocol, port) in self.rules:
                del self.rules[(protocol, port)]
                self._remove_tc_limit(protocol, port)

    def _parse_limit(self, limit_str):
        """解析限制值字符串（如 '2MB/s'）为字节数"""
        value = float(limit_str[:-4])
        unit = limit_str[-4:-2].upper()
        multiplier = {
            'KB': 1024,
            'MB': 1024 * 1024,
            'GB': 1024 * 1024 * 1024
        }.get(unit, 1)
        return int(value * multiplier)

    def _apply_tc_limit(self, protocol, port, limit_bytes):
        """应用 tc 流量限制"""
        try:
            interface = self._get_default_interface()
            
            # 检查是否已存在root qdisc
            result = subprocess.run(["tc", "qdisc", "show", "dev", interface], 
                                 capture_output=True, text=True)
            if "htb" not in result.stdout:
                # 创建root qdisc
                subprocess.run([
                    "tc", "qdisc", "add", "dev", interface, "root", "handle", "1:", "htb"
                ], check=True)
            
            # 创建类
            class_id = f"1:{port}"
            subprocess.run([
                "tc", "class", "add", "dev", interface, "parent", "1:", 
                "classid", class_id, "htb", "rate", f"{limit_bytes}bps"
            ], check=True)
            
            # 添加过滤器
            subprocess.run([
                "tc", "filter", "add", "dev", interface, "protocol", "ip",
                "parent", "1:0", "prio", "1", "u32", "match", "ip", 
                "dport" if protocol == "TCP" else "sport", str(port),
                "0xffff", "flowid", class_id
            ], check=True)
            
        except subprocess.CalledProcessError as e:
            print(f"应用流量限制失败: {e}")

    def _get_default_interface(self):
        """获取默认网络接口"""
        try:
            result = subprocess.run(["ip", "route", "show", "default"], 
                                 capture_output=True, text=True, check=True)
            return result.stdout.split()[4]
        except:
            return "eth0"  # 默认返回eth0

    def _remove_tc_limit(self, protocol, port):
        """移除 tc 流量限制"""
        try:
            interface = self._get_default_interface()
            class_id = f"1:{port}"
            
            # 移除过滤器
            subprocess.run([
                "tc", "filter", "del", "dev", interface, "protocol", "ip",
                "parent", "1:0", "prio", "1"
            ], check=True)
            
            # 移除类
            subprocess.run([
                "tc", "class", "del", "dev", interface, "classid", class_id
            ], check=True)
            
        except subprocess.CalledProcessError as e:
            print(f"移除流量限制失败: {e}")

    def update_stats(self):
        """更新流量统计信息"""
        while True:
            for protocol, port in list(self.rules.keys()):
                try:
                    current_speed = self._get_port_traffic(protocol, port)
                    limit = self.rules.get((protocol, port), 0)
                    
                    with self.lock:
                        self.stats[(protocol, port)].update({
                            'current_speed': current_speed,
                            'limit': limit,
                            'status': 'Warning' if current_speed > limit * 0.8 else 'Normal'
                        })
                except Exception as e:
                    print(f"更新统计信息失败: {e}")
            
            time.sleep(1)

    def _get_port_traffic(self, protocol, port):
        """获取指定端口的当前流量"""
        total_bytes = 0
        try:
            # 使用 iptables 获取流量统计
            result = subprocess.run([
                "iptables", "-L", "-n", "-v", "-x"
            ], capture_output=True, text=True, check=True)
            # 这里需要解析iptables输出来获取具体端口的流量
            return total_bytes
        except:
            return 0

    def get_current_stats(self):
        """获取当前统计信息"""
        with self.lock:
            return [
                {
                    'protocol': protocol,
                    'port': port,
                    'current': self._format_bytes(stats['current_speed']),
                    'limit': self._format_bytes(self.rules.get((protocol, port), 0)),
                    'status': stats['status']
                }
                for (protocol, port), stats in self.stats.items()
            ]

    @staticmethod
    def _format_bytes(bytes_value):
        """格式化字节数"""
        for unit in ['B/s', 'KB/s', 'MB/s', 'GB/s']:
            if bytes_value < 1024:
                return f"{bytes_value:.2f}{unit}"
            bytes_value /= 1024
        return f"{bytes_value:.2f}TB/s"

# 创建控制器实例
auth_manager = AuthManager()
controller = TrafficController()

def require_auth(f):
    """认证装饰器"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not auth_manager.check_ip(request.remote_addr):
            abort(403, description="IP not allowed")
        
        token = request.headers.get('Authorization')
        if not token or not auth_manager.verify_token(token):
            abort(401, description="Invalid or expired token")
            
        return f(*args, **kwargs)
    return decorated

@app.route('/api/login', methods=['POST'])
def login():
    if not auth_manager.check_ip(request.remote_addr):
        abort(403, description="IP not allowed")
        
    data = request.json
    if not data or 'password' not in data:
        abort(400, description="Password required")
        
    if auth_manager.verify_password(data['password']):
        token = auth_manager.generate_token()
        return jsonify({'token': token})
    else:
        abort(401, description="Invalid password")

@app.route('/api/rules', methods=['GET'])
@require_auth
def get_rules():
    return jsonify(controller.get_current_stats())

@app.route('/api/rules', methods=['POST'])
@require_auth
def add_rule():
    data = request.json
    try:
        controller.add_rule(data['protocol'], int(data['port']), data['limit'])
        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@app.route('/api/rules/<protocol>/<int:port>', methods=['DELETE'])
@require_auth
def remove_rule(protocol, port):
    try:
        controller.remove_rule(protocol, port)
        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

def main():
    # 启动统计信息更新线程
    stats_thread = threading.Thread(target=controller.update_stats, daemon=True)
    stats_thread.start()
    
    # 启动API服务器
    app.run(host='0.0.0.0', port=5000)

if __name__ == '__main__':
    main()
