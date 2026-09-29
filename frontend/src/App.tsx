import { BrowserRouter, Routes, Route, NavLink, Navigate, Outlet } from 'react-router-dom';
import {
  LayoutDashboard,
  FileText,
  Server,
  AlertTriangle,
  Activity,
  Shield,
  LogOut,
  User,
  Settings,
} from 'lucide-react';

import {
  OverviewPage,
  EventsPage,
  EventDetailPage,
  LineagePage,
  SourcesPage,
  SchemaDriftPage,
  ParsingFailuresPage,
  NormalizationFailuresPage,
  HealthPage,
  AnomaliesPage,
} from './pages';
import { LoginPage } from './pages/Login';
import { AuthProvider, useAuth } from './context/AuthContext';
import { Dropdown } from './components';

interface NavItem {
  path: string;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  permission: string;
}

function Navigation() {
  const { user, logout, hasPermission } = useAuth();

  const navItems: NavItem[] = [
    { path: '/', label: 'Overview', icon: LayoutDashboard, permission: 'events:view' },
    { path: '/events', label: 'Events', icon: FileText, permission: 'events:search' },
    { path: '/anomalies', label: 'Anomalies', icon: AlertTriangle, permission: 'analytics:view' },
    { path: '/sources', label: 'Sources', icon: Server, permission: 'sources:view' },
    { path: '/schema-drift', label: 'Schema Drift', icon: AlertTriangle, permission: 'schema:view' },
    { path: '/parsing-failures', label: 'Parsing Failures', icon: FileText, permission: 'events:view' },
    { path: '/normalization-failures', label: 'Norm. Failures', icon: Shield, permission: 'events:view' },
    { path: '/health', label: 'Health', icon: Activity, permission: 'health:view' },
  ];

  const visibleItems = navItems.filter((item) => hasPermission(item.permission));

  const userMenuItems = [
    { label: 'Profile', icon: User, onClick: () => {}, variant: 'default' as const },
    { label: 'Settings', icon: Settings, onClick: () => {}, variant: 'default' as const },
    { label: 'Logout', icon: LogOut, onClick: logout, variant: 'destructive' as const },
  ];

  return (
    <nav className="bg-dark-100 border-b border-gray-700">
      <div className="max-w-7xl mx-auto px-4">
        <div className="flex items-center h-16">
          <div className="flex items-center gap-2 mr-8">
            <Shield className="w-8 h-8 text-primary-500" />
            <span className="text-xl font-bold">ULPF</span>
          </div>
          <div className="flex-1 flex space-x-1">
            {visibleItems.map((item) => (
              <NavLink
                key={item.path}
                to={item.path}
                className={({ isActive }) =>
                  `flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                    isActive
                      ? 'bg-primary-600 text-white'
                      : 'text-gray-400 hover:text-white hover:bg-dark-200'
                  }`
                }
              >
                <item.icon className="w-4 h-4" />
                {item.label}
              </NavLink>
            ))}
          </div>
          <div className="flex items-center gap-4">
            {user && (
              <>
                <span className="text-sm text-gray-300 hidden sm:block">
                  {user.username} ({user.role})
                </span>
                <Dropdown
                  items={userMenuItems.map((item) => ({
                    label: item.label,
                    icon: <item.icon className="w-4 h-4" />,
                    onClick: item.onClick,
                    variant: item.variant,
                  }))}
                  triggerLabel=""
                  triggerIcon={<User className="w-4 h-4" />}
                />
              </>
            )}
          </div>
        </div>
      </div>
    </nav>
  );
}

function Footer() {
  return (
    <footer className="bg-dark-100 border-t border-gray-700 mt-auto">
      <div className="max-w-7xl mx-auto px-4 py-4">
        <div className="flex items-center justify-between text-sm text-gray-400">
          <span>ULPF Dashboard - Universal Log Pre-processing Framework</span>
          <span>SIH 2026 - PS ID 26156 - NTRO</span>
        </div>
      </div>
    </footer>
  );
}

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { user, isLoading } = useAuth();

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-dark-200">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-500" />
      </div>
    );
  }

  if (!user) {
    return <Navigate to="/login" replace />;
  }

  return <>{children}</>;
}

function PublicRoute({ children }: { children: React.ReactNode }) {
  const { user, isLoading } = useAuth();

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-dark-200">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-500" />
      </div>
    );
  }

  if (user) {
    return <Navigate to="/" replace />;
  }

  return <>{children}</>;
}

function AppRoutes() {
  return (
    <Routes>
      <Route path="/login" element={<PublicRoute><LoginPage /></PublicRoute>} />
      <Route element={<ProtectedRoute><Outlet /></ProtectedRoute>}>
        <Route path="/" element={<OverviewPage />} />
        <Route path="/events" element={<EventsPage />} />
        <Route path="/events/:eventId" element={<EventDetailPage />} />
        <Route path="/lineage/raw/:rawEventId" element={<LineagePage />} />
        <Route path="/anomalies" element={<AnomaliesPage />} />
        <Route path="/sources" element={<SourcesPage />} />
        <Route path="/schema-drift" element={<SchemaDriftPage />} />
        <Route path="/parsing-failures" element={<ParsingFailuresPage />} />
        <Route path="/normalization-failures" element={<NormalizationFailuresPage />} />
        <Route path="/health" element={<HealthPage />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

function App() {
  return (
    <AuthProvider>
      <BrowserRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
        <div className="min-h-screen flex flex-col bg-dark-200">
          <Navigation />
          <main className="flex-1 max-w-7xl w-full mx-auto px-4 py-6">
            <AppRoutes />
          </main>
          <Footer />
        </div>
      </BrowserRouter>
    </AuthProvider>
  );
}

export default App;