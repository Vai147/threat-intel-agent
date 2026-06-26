import type { ReactNode } from "react";
import "./ui.css";

interface CardProps {
  label?: string;
  children: ReactNode;
  className?: string;
  /** Retained for API compatibility; flat Material cards look the same. */
  accent?: boolean;
}

export function Card({ label, children, className = "" }: CardProps) {
  return (
    <section className={`card ${className}`}>
      {label && <header className="card__label">{label}</header>}
      {children}
    </section>
  );
}
