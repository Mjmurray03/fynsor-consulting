import type { Metadata } from 'next';
import { Inter } from 'next/font/google';
import './globals.css';
// Analytics temporarily disabled for build
// import GoogleAnalytics from '@/components/GoogleAnalytics';
// import AnalyticsProvider from '@/components/AnalyticsProvider';
// import { GA_MEASUREMENT_ID } from '@/lib/gtag';

const inter = Inter({ subsets: ['latin'], variable: '--font-inter' });

export const metadata: Metadata = {
  title: 'Fynsor - Where Finance Meets Intelligence',
  description: 'Institutional-grade commercial real estate financial modeling and analysis.',
  keywords: 'commercial real estate, financial modeling, institutional finance, CRE analysis',
  authors: [{ name: 'Fynsor' }],
};

export const viewport = {
  width: 'device-width',
  initialScale: 1,
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className={inter.variable}>
      <head>
        {/* Google Analytics temporarily disabled for build */}
      </head>
      <body className={`${inter.className} antialiased`}>
        {children}
      </body>
    </html>
  );
}