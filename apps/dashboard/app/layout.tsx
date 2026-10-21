import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'SkillSentry — local security scanner for agent skills',
  description:
    'Scan SKILL.md files and MCP server configs for poisoning, exfiltration and hijack patterns. Static rules + local open-weight model. Nothing leaves your machine.'
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
