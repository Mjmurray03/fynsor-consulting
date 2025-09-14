'use client';

import React from 'react';

interface SectionProps {
  children: React.ReactNode;
  className?: string;
  containerClassName?: string;
  fullWidth?: boolean;
}

const Section: React.FC<SectionProps> = ({
  children,
  className = '',
  containerClassName = '',
  fullWidth = false
}) => {
  return (
    <section className={`py-16 ${className}`}>
      <div className={`
        ${fullWidth ? 'w-full' : 'max-w-7xl mx-auto px-4 sm:px-6 lg:px-8'}
        ${containerClassName}
      `}>
        {children}
      </div>
    </section>
  );
};

export default Section;