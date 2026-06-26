import type { ReactNode } from "react";
import "./ui.css";

interface TagProps {
  children: ReactNode;
  tone?: "default" | "danger" | "accent";
  mono?: boolean;
}

export function Tag({ children, tone = "default", mono }: TagProps) {
  return (
    <span className={`tag tag--${tone} ${mono ? "mono" : ""}`}>{children}</span>
  );
}
