import type { ReactNode } from "react";
import { Link } from "react-router-dom";

export function PageHeader({
  title,
  action,
}: {
  title: string;
  action?: ReactNode;
}) {
  return (
    <div className="flex items-center justify-between px-6 py-4 border-b border-zinc-200 bg-white">
      <h1 className="text-xl font-semibold text-zinc-900">{title}</h1>
      {action}
    </div>
  );
}

export function Btn({
  children,
  onClick,
  variant = "primary",
  disabled,
  type = "button",
}: {
  children: ReactNode;
  onClick?: () => void;
  variant?: "primary" | "danger" | "secondary";
  disabled?: boolean;
  type?: "button" | "submit";
}) {
  const base = "px-3 py-1.5 text-sm font-medium rounded disabled:opacity-50";
  const styles = {
    primary: "bg-zinc-900 text-white hover:bg-zinc-700",
    danger: "bg-red-600 text-white hover:bg-red-500",
    secondary: "bg-white text-zinc-700 border border-zinc-300 hover:bg-zinc-50",
  };
  return (
    <button
      type={type}
      className={`${base} ${styles[variant]}`}
      onClick={onClick}
      disabled={disabled}
    >
      {children}
    </button>
  );
}

export function LinkBtn({
  to,
  children,
}: {
  to: string;
  children: ReactNode;
}) {
  return (
    <Link
      to={to}
      className="px-3 py-1.5 text-sm font-medium rounded bg-zinc-900 text-white hover:bg-zinc-700"
    >
      {children}
    </Link>
  );
}

export function Badge({
  children,
  color = "zinc",
}: {
  children: ReactNode;
  color?: "green" | "red" | "yellow" | "zinc" | "blue";
}) {
  const styles = {
    green: "bg-green-100 text-green-800",
    red: "bg-red-100 text-red-800",
    yellow: "bg-yellow-100 text-yellow-800",
    zinc: "bg-zinc-100 text-zinc-800",
    blue: "bg-blue-100 text-blue-800",
  };
  return (
    <span className={`px-2 py-0.5 text-xs font-medium rounded-full ${styles[color]}`}>
      {children}
    </span>
  );
}

export function Table({
  headers,
  children,
}: {
  headers: string[];
  children: ReactNode;
}) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm text-left">
        <thead className="text-xs text-zinc-500 uppercase bg-zinc-50 border-b">
          <tr>
            {headers.map((h) => (
              <th key={h} className="px-6 py-3">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-zinc-100">{children}</tbody>
      </table>
    </div>
  );
}

export function Td({ children }: { children: ReactNode }) {
  return <td className="px-6 py-3">{children}</td>;
}

export function ErrorBox({ message }: { message: string }) {
  return (
    <div className="m-6 p-4 bg-red-50 border border-red-200 rounded text-red-700 text-sm">
      {message}
    </div>
  );
}

export function Loading() {
  return (
    <div className="p-6 text-zinc-400 text-sm">Loading...</div>
  );
}

export function DetailRow({
  label,
  children,
}: {
  label: string;
  children: ReactNode;
}) {
  return (
    <div className="flex py-2 border-b border-zinc-100">
      <dt className="w-40 shrink-0 text-zinc-500 text-sm">{label}</dt>
      <dd className="text-sm text-zinc-900">{children}</dd>
    </div>
  );
}

export function Card({ children }: { children: ReactNode }) {
  return (
    <div className="m-6 bg-white rounded-lg border border-zinc-200 overflow-hidden">
      {children}
    </div>
  );
}
