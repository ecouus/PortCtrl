import React, { useState, useEffect } from 'react';

const API_BASE_URL = 'http://localhost:5000';

const LoginForm = ({ onLogin }) => {
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const response = await fetch(`${API_BASE_URL}/api/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ password }),
      });

      if (!response.ok) {
        throw new Error('密码错误');
      }

      const data = await response.json();
      localStorage.setItem('authToken', data.token);
      onLogin(data.token);
    } catch (err) {
      setError('登录失败：' + err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-100">
      <div className="bg-white p-8 rounded-lg shadow-md w-full max-w-md">
        <h2 className="text-2xl font-bold mb-6">登录到流量监控系统</h2>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="请输入密码"
              className="w-full p-2 border rounded"
              disabled={loading}
            />
          </div>
          {error && (
            <div className="bg-red-100 text-red-700 p-3 rounded">
              {error}
            </div>
          )}
          <button
            type="submit"
            disabled={loading}
            className="w-full bg-blue-500 text-white p-2 rounded hover:bg-blue-600 disabled:bg-blue-300"
          >
            {loading ? '登录中...' : '登录'}
          </button>
        </form>
      </div>
    </div>
  );
};

const TrafficControl = () => {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [token, setToken] = useState(localStorage.getItem('authToken'));
  const [newRule, setNewRule] = useState({
    protocol: 'TCP',
    port: '',
    limit: ''
  });
  const [stats, setStats] = useState([]);
  const [error, setError] = useState('');

  const handleLogin = (newToken) => {
    setToken(newToken);
    setIsAuthenticated(true);
  };

  useEffect(() => {
    if (!token) return;

    const fetchStats = async () => {
      try {
        const response = await fetch(`${API_BASE_URL}/api/rules`, {
          headers: {
            'Authorization': token
          }
        });
        
        if (!response.ok) {
          if (response.status === 401) {
            localStorage.removeItem('authToken');
            setToken(null);
            setIsAuthenticated(false);
            return;
          }
          throw new Error('获取数据失败');
        }
        
        const data = await response.json();
        setStats(data);
      } catch (err) {
        console.error('获取统计信息失败:', err);
      }
    };

    const interval = setInterval(fetchStats, 1000);
    return () => clearInterval(interval);
  }, [token]);

  const handleAddRule = async () => {
    if (!newRule.port || !newRule.limit) {
      setError('端口和限制值都必须填写');
      return;
    }

    try {
      const response = await fetch(`${API_BASE_URL}/api/rules`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': token
        },
        body: JSON.stringify(newRule),
      });

      if (!response.ok) {
        throw new Error('添加规则失败');
      }

      setNewRule({ protocol: 'TCP', port: '', limit: '' });
      setError('');
    } catch (err) {
      setError(err.message);
    }
  };

  const handleRemoveRule = async (protocol, port) => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/rules/${protocol}/${port}`, {
        method: 'DELETE',
        headers: {
          'Authorization': token
        }
      });

      if (!response.ok) {
        throw new Error('删除规则失败');
      }
    } catch (err) {
      setError('删除规则失败');
    }
  };

  if (!isAuthenticated || !token) {
    return <LoginForm onLogin={handleLogin} />;
  }

  return (
    <div className="p-4">
      <div className="bg-white rounded-lg shadow-md p-6 mb-4">
        <h2 className="text-2xl font-bold mb-4">端口流量限制配置</h2>
        <div className="flex gap-4 mb-4">
          <select
            className="border rounded px-3 py-2"
            value={newRule.protocol}
            onChange={(e) => setNewRule({ ...newRule, protocol: e.target.value })}
          >
            <option>TCP</option>
            <option>UDP</option>
          </select>
          <input
            type="number"
            placeholder="端口号"
            value={newRule.port}
            onChange={(e) => setNewRule({ ...newRule, port: e.target.value })}
            className="border rounded px-3 py-2 w-32"
          />
          <input
            type="text"
            placeholder="限制值 (例如: 2MB/s)"
            value={newRule.limit}
            onChange={(e) => setNewRule({ ...newRule, limit: e.target.value })}
            className="border rounded px-3 py-2 w-48"
          />
          <button
            onClick={handleAddRule}
            className="bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600"
          >
            添加限制规则
          </button>
        </div>

        {error && (
          <div className="bg-red-100 text-red-700 p-3 rounded mb-4">
            {error}
          </div>
        )}

        <div className="overflow-x-auto">
          <table className="min-w-full">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">协议</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">端口</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">当前流量</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">限制值</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">状态</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">操作</th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {stats.map((stat) => (
                <tr key={`${stat.protocol}-${stat.port}`}>
                  <td className="px-6 py-4 whitespace-nowrap">{stat.protocol}</td>
                  <td className="px-6 py-4 whitespace-nowrap">{stat.port}</td>
                  <td className="px-6 py-4 whitespace-nowrap">{stat.current}</td>
                  <td className="px-6 py-4 whitespace-nowrap">{stat.limit}</td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className={`px-2 py-1 text-xs rounded-full ${
                      stat.status === 'Warning'
                        ? 'bg-yellow-100 text-yellow-800'
                        : 'bg-green-100 text-green-800'
                    }`}>
                      {stat.status}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <button
                      onClick={() => handleRemoveRule(stat.protocol, stat.port)}
                      className="text-red-600 hover:text-red-900"
                    >
                      删除
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default TrafficControl;
