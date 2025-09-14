'use client';

import React from 'react';
import Image from 'next/image';

interface LogoBannerProps {
  width?: number;
  height?: number;
  className?: string;
  variant?: 'banner' | 'cover';
  animate?: boolean;
}

const LogoBanner: React.FC<LogoBannerProps> = ({
  width = 800,
  height = 200,
  className = '',
  variant = 'banner',
  animate = false
}) => {
  const imageSrc = variant === 'cover' ? '/images/cover.png' : '/images/banner.png';
  const altText = variant === 'cover'
    ? 'Fynsor Consulting - Universal Cover'
    : 'Fynsor Consulting - Professional Banner';

  return (
    <div
      className={`relative overflow-hidden ${className}`}
      style={{ width, height }}
    >
      <Image
        src={imageSrc}
        alt={altText}
        width={width}
        height={height}
        className={`
          object-cover
          ${animate ? 'animate-fadeIn' : ''}
          transition-all duration-500
        `}
        style={{
          filter: 'contrast(1.05) brightness(0.98)',
        }}
        priority={width >= 400} // Prioritize loading for large banners
      />

      {/* Overlay for better text readability if needed */}
      <div className="absolute inset-0 bg-gradient-to-r from-black/10 to-transparent opacity-0 hover:opacity-100 transition-opacity duration-300" />
    </div>
  );
};

export default LogoBanner;