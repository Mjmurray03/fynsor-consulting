import type { Metadata } from 'next';
import { Inter } from 'next/font/google';
import './globals.css';
import GoogleAnalytics from '@/components/GoogleAnalytics';
import AnalyticsProvider from '@/components/AnalyticsProvider';
import { GA_MEASUREMENT_ID } from '@/lib/gtag';

const inter = Inter({ subsets: ['latin'], variable: '--font-inter' });

export const metadata: Metadata = {
  title: 'Fynsor - Where Finance Meets Intelligence',
  description: 'Institutional-grade commercial real estate financial modeling and analysis.',
  keywords: 'commercial real estate, financial modeling, institutional finance, CRE analysis',
  authors: [{ name: 'Fynsor' }],
  viewport: 'width=device-width, initial-scale=1',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className={inter.variable}>
      <head>
        {/* Google Analytics - Only loads in production */}
        {GA_MEASUREMENT_ID && (
          <GoogleAnalytics measurementId={GA_MEASUREMENT_ID} />
        )}
      </head>
      <body className={`${inter.className} antialiased`}>
        <AnalyticsProvider>
          {children}
        </AnalyticsProvider>
      </body>
    </html>
  );
}