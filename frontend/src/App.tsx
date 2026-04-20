import { BrowserRouter, Routes, Route, NavLink, Navigate } from "react-router-dom";
import { AuthProvider, useAuth } from "./auth";
import Dashboard from "./pages/Dashboard";
import Users from "./pages/Users";
import UserDetail from "./pages/UserDetail";
import UserCreate from "./pages/UserCreate";
import Roles from "./pages/Roles";
import RoleDetail from "./pages/RoleDetail";
import RoleCreate from "./pages/RoleCreate";
import Issuers from "./pages/Issuers";
import IssuerDetail from "./pages/IssuerDetail";
import Keys from "./pages/Keys";
import Tokens from "./pages/Tokens";

const navItems = [
  { to: "/", label: "Dashboard" },
  { to: "/users", label: "Users" },
  { to: "/roles", label: "Roles" },
  { to: "/issuers", label: "Issuers" },
  { to: "/keys", label: "Keys" },
  { to: "/tokens", label: "Tokens" },
];

function Layout() {
  const { user } = useAuth();
  return (
    <div className="flex h-screen bg-zinc-50">
      <nav className="w-56 shrink-0 bg-zinc-900 text-zinc-300 flex flex-col">
        <div className="px-4 py-5 text-white font-semibold text-lg border-b border-zinc-700">
          Auth Admin
        </div>
        <div className="flex-1 py-2">
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === "/"}
              className={({ isActive }) =>
                `block px-4 py-2 text-sm hover:bg-zinc-800 ${isActive ? "bg-zinc-800 text-white" : ""}`
              }
            >
              {item.label}
            </NavLink>
          ))}
        </div>
        <div className="px-4 py-3 border-t border-zinc-700 text-xs text-zinc-500 truncate">
          {user.email}
        </div>
      </nav>
      <main className="flex-1 overflow-auto">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/users" element={<Users />} />
          <Route path="/users/new" element={<UserCreate />} />
          <Route path="/users/:id" element={<UserDetail />} />
          <Route path="/roles" element={<Roles />} />
          <Route path="/roles/new" element={<RoleCreate />} />
          <Route path="/roles/:id" element={<RoleDetail />} />
          <Route path="/issuers" element={<Issuers />} />
          <Route path="/issuers/:id" element={<IssuerDetail />} />
          <Route path="/keys" element={<Keys />} />
          <Route path="/tokens" element={<Tokens />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
    </div>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Layout />
      </AuthProvider>
    </BrowserRouter>
  );
}
