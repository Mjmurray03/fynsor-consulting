'use client';

import React, { useEffect, useState } from 'react';
import Script from 'next/script';

interface GoogleAnalyticsProps {
  measurementId: string;
}

const GoogleAnalytics: React.FC<GoogleAnalyticsProps> = ({ measurementId }) => {
  const [consentGiven, setConsentGiven] = useState<boolean | null>(null);
  const [showBanner, setShowBanner] = useState(false);

  useEffect(() => {
    // Check if we're in production environment
    const isProduction = process.env.NODE_ENV === 'production';

    if (!isProduction) {
      console.log('Google Analytics disabled in development mode');
      return;
    }

    // Check for existing consent
    const existingConsent = localStorage.getItem('ga-consent');

    if (existingConsent === null) {
      // No consent decision made yet, show banner
      setShowBanner(true);
    } else {
      // Use existing consent decision
      const consent = existingConsent === 'true';
      setConsentGiven(consent);

      if (consent) {
        initializeGA();
      }
    }
  }, []);

  const initializeGA = () => {
    // Initialize Google Analytics
    window.gtag('config', measurementId, {
      // Privacy-focused configuration
      anonymize_ip: true,
      allow_google_signals: false,
      allow_ad_personalization_signals: false,
      restricted_data_processing: true,
    });

    // Track initial page view
    window.gtag('event', 'page_view', {
      page_title: document.title,
      page_location: window.location.href,
    });
  };

  const handleConsent = (consent: boolean) => {
    // Store consent decision
    localStorage.setItem('ga-consent', consent.toString());
    setConsentGiven(consent);
    setShowBanner(false);

    if (consent) {
      initializeGA();
    } else {
      // Disable Google Analytics
      window.gtag('consent', 'update', {
        analytics_storage: 'denied',
        ad_storage: 'denied',
      });
    }
  };

  // Only render in production
  if (process.env.NODE_ENV !== 'production') {
    return null;
  }

  return (
    <>
      {/* Google Analytics Scripts */}
      <Script
        src={`https://www.googletagmanager.com/gtag/js?id=${measurementId}`}
        strategy="afterInteractive"
      />
      <Script id="google-analytics" strategy="afterInteractive">
        {`
          window.dataLayer = window.dataLayer || [];
          function gtag(){dataLayer.push(arguments);}
          gtag('js', new Date());

          // Set default consent
          gtag('consent', 'default', {
            analytics_storage: 'denied',
            ad_storage: 'denied',
            wait_for_update: 500,
          });
        `}
      </Script>

      {/* GDPR Consent Banner */}
      {showBanner && (
        <div className="fixed bottom-0 left-0 right-0 z-50 bg-black border-t border-gray-600 p-4 shadow-lg">
          <div className="max-w-6xl mx-auto flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
            <div className="flex-1">
              <h3 className="text-white font-semibold text-sm mb-2">
                Privacy & Analytics
              </h3>
              <p className="text-gray-300 text-xs leading-relaxed">
                We use Google Analytics to understand how visitors interact with our website.
                This helps us improve our services for commercial real estate professionals.
                Your data is anonymized and we don't share personal information.
              </p>
            </div>

            <div className="flex gap-3 flex-shrink-0">
              <button
                onClick={() => handleConsent(false)}
                className="px-4 py-2 text-xs border border-gray-600 text-gray-300 hover:text-white hover:border-gray-400 transition-colors duration-200"
              >
                Decline
              </button>
              <button
                onClick={() => handleConsent(true)}
                className="px-4 py-2 text-xs bg-white text-black hover:bg-gray-100 transition-colors duration-200"
              >
                Accept Analytics
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
};

// Global gtag function declaration
declare global {
  interface Window {
    gtag: (...args: any[]) => void;
    dataLayer: any[];
  }
}

export default GoogleAnalytics;