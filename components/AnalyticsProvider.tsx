'use client';

import React from 'react';
import { usePageTracking } from '@/hooks/usePageTracking';

/**
 * Analytics Provider Component
 * Handles automatic page view tracking and analytics initialization
 */
interface AnalyticsProviderProps {
  children: React.ReactNode;
}

const AnalyticsProvider: React.FC<AnalyticsProviderProps> = ({ children }) => {
  // Automatically track page views on route changes
  usePageTracking();

  return <>{children}</>;
};

export default AnalyticsProvider;