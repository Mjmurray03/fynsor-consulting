'use client';

import React from 'react';
import Navigation from '../navigation/Navigation';

interface LayoutProps {
  children: React.ReactNode;
  className?: string;
}

const Layout: React.FC<LayoutProps> = ({ children, className = '' }) => {
  return (
    <div className="min-h-screen bg-white text-black font-inter">
      <Navigation />
      <main className={`pt-16 ${className}`}>
        {children}
      </main>
    </div>
  );
};

export default Layout;