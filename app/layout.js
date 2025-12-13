import "./globals.css";

export const metadata = {
  title: "IP Intelligence",
  description: "Check IP reputation with AbuseIPDB and VirusTotal",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
