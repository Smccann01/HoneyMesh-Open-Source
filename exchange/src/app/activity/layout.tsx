import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Live Exchange Defense",
  description: "A privacy-safe, live view of active HoneyMesh Exchange protection controls.",
  alternates: { canonical: "/activity" },
  robots: { index: false, follow: false },
};

export default function ActivityLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return children;
}
