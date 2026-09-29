import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Lock, User, Eye, EyeOff, Loader2 } from 'lucide-react';
import { Card, Input, Button, ErrorState } from '../components';
import { useAuth } from '../context/AuthContext';

export function LoginPage() {
  const navigate = useNavigate();
  const { login, isLoading: authLoading } = useAuth();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setIsLoading(true);

    const success = await login(username, password);
    if (success) {
      navigate('/');
    } else {
      setError('Invalid username or password');
    }
    setIsLoading(false);
  };

  // Demo credentials hint
  const demoUsers = [
    { username: 'admin', password: 'ulpf-admin-demo', role: 'Administrator' },
    { username: 'analyst', password: 'ulpf-analyst-demo', role: 'Security Analyst' },
    { username: 'viewer', password: 'ulpf-viewer-demo', role: 'Read-only Viewer' },
  ];

  if (authLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-dark-200">
        <Loader2 className="w-8 h-8 text-primary-500 animate-spin" />
      </div>
    );
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-dark-200 px-4">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <div className="flex items-center justify-center gap-2 mb-4">
            <Lock className="w-10 h-10 text-primary-500" />
            <span className="text-2xl font-bold">ULPF</span>
          </div>
          <h1 className="text-xl font-semibold">Sign in to Dashboard</h1>
          <p className="text-gray-400 mt-1">Universal Log Pre-processing Framework</p>
        </div>

        <Card className="space-y-6">
          <form onSubmit={handleSubmit} className="space-y-4">
            {error && (
              <ErrorState message={error} />
            )}

            <div className="space-y-2">
              <label htmlFor="username" className="block text-sm font-medium text-gray-300">
                Username
              </label>
              <div className="relative">
                <User className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
                <Input
                  id="username"
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="Enter username"
                  className="pl-10"
                  autoComplete="username"
                  disabled={isLoading}
                  required
                />
              </div>
            </div>

            <div className="space-y-2">
              <label htmlFor="password" className="block text-sm font-medium text-gray-300">
                Password
              </label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
                <Input
                  id="password"
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Enter password"
                  className="pl-10 pr-10"
                  autoComplete="current-password"
                  disabled={isLoading}
                  required
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-white"
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                >
                  {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                </button>
              </div>
            </div>

            <Button type="submit" className="w-full" disabled={isLoading} loading={isLoading}>
              Sign In
            </Button>
          </form>

          <div className="border-t border-gray-700 pt-4">
            <p className="text-sm text-gray-400 mb-3 text-center">Demo Credentials</p>
            <div className="space-y-2 text-sm">
              {demoUsers.map((demo) => (
                <div
                  key={demo.username}
                  className="flex items-center justify-between p-2 bg-dark-200 rounded cursor-pointer hover:bg-dark-300 transition-colors"
                  onClick={() => {
                    setUsername(demo.username);
                    setPassword(demo.password);
                  }}
                >
                  <span className="font-medium text-gray-100">{demo.username}</span>
                  <span className="text-gray-400">{demo.role}</span>
                </div>
              ))}
            </div>
            <p className="text-xs text-gray-500 mt-2 text-center">
              Click any credential to auto-fill
            </p>
          </div>
        </Card>

        <div className="mt-6 text-center text-sm text-gray-400">
          <p>SIH 2026 - PS ID 26156 - NTRO</p>
        </div>
      </div>
    </div>
  );
}