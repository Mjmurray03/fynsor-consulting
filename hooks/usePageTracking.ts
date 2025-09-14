'use client';

import { useEffect } from 'react';
import { usePathname } from 'next/navigation';
import { trackPageView } from '@/lib/gtag';

/**
 * Hook to automatically track page views in Google Analytics
 * For use in Next.js App Router with client components
 */
export const usePageTracking = () => {
  const pathname = usePathname();

  useEffect(() => {
    // Track page view when pathname changes
    if (pathname && typeof window !== 'undefined') {
      const url = window.location.href;
      const title = document.title;

      // Small delay to ensure page has loaded
      setTimeout(() => {
        trackPageView(url, title);
      }, 100);
    }
  }, [pathname]);
};

export default usePageTracking;