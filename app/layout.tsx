import type { Metadata, Viewport } from "next";
import { IBM_Plex_Sans_Arabic } from "next/font/google";
import "./globals.css";

const ibmPlexArabic = IBM_Plex_Sans_Arabic({
  subsets: ["arabic"],
  weight: ["300", "400", "500", "600", "700"],
  variable: "--font-arabic",
  display: "swap",
});

export const metadata: Metadata = {
  title: "حارس | HARIS — كاشف الاحتيال وبصمة التهديد الذكية",
  description: "أداة أمنية عربية ذكية لتحليل الرسائل والروابط ولقطات الشاشة المشبوهة، واستخراج بصمة الاحتيال (Scam DNA) وتقديم إرشادات وقائية فورية.",
  icons: {
    icon: "/favicon.ico",
  },
};

export const viewport: Viewport = {
  themeColor: "#080c14",
  width: "device-width",
  initialScale: 1,
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="ar" dir="rtl" className={ibmPlexArabic.variable}>
      <body className={ibmPlexArabic.className}>
        {children}
      </body>
    </html>
  );
}
