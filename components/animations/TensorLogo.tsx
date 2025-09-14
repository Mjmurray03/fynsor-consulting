'use client';

import React from 'react';
import Image from 'next/image';

interface TensorLogoProps {
  size?: number;
  animate?: boolean;
  className?: string;
  variant?: 'image' | 'dots' | 'auto';
}

const TensorLogo: React.FC<TensorLogoProps> = ({
  size = 32,
  animate = false,
  className = '',
  variant = 'auto'
}) => {
  // 4x4 grid pattern forming an "F" shape
  // 1 = white dot, 0 = transparent
  const pattern = [
    [1, 1, 1, 1], // Top horizontal line
    [1, 0, 0, 0], // Left vertical
    [1, 1, 1, 0], // Middle horizontal line
    [1, 0, 0, 0]  // Bottom left vertical
  ];

  // Use image for larger sizes (better detail), dots for smaller sizes (better performance)
  const shouldUseImage = variant === 'image' || (variant === 'auto' && size >= 64);

  // Image variant - uses uploaded logo
  if (shouldUseImage) {
    return (
      <div className={`relative ${className}`} style={{ width: size, height: size }}>
        <Image
          src="/images/logo.png"
          alt="Fynsor Consulting - Tensor Logo"
          width={size}
          height={size}
          className={`
            tensor-logo
            ${animate ? 'animate-pulse' : ''}
            transition-all duration-300
          `}
          style={{
            animationDuration: animate ? '2s' : '0s',
            animationIterationCount: animate ? 'infinite' : '1'
          }}
          priority={size >= 100} // Prioritize loading for large logos
          onError={(e) => {
            // Fallback to dots pattern if image fails to load
            console.warn('Logo image failed to load, falling back to dots pattern');
          }}
        />
      </div>
    );
  }

  // Dots variant - algorithmic tensor pattern

  return (
    <div
      className={`relative ${className}`}
      style={{
        width: size,
        height: size,
        display: 'grid',
        gridTemplateColumns: 'repeat(4, 1fr)',
        gridTemplateRows: 'repeat(4, 1fr)',
        gap: '2px',
        padding: '2px',
        border: '1px solid #666666',
        backgroundColor: 'transparent'
      }}
    >
      {pattern.flat().map((dot, index) => {
        const row = Math.floor(index / 4);
        const col = index % 4;
        const delay = animate ? (row * 4 + col) * 100 : 0;

        return (
          <div
            key={index}
            className={`
              ${dot ? 'bg-white' : 'bg-transparent'}
              ${animate ? 'animate-pulse' : ''}
              rounded-full
              transition-all
              duration-300
            `}
            style={{
              width: '100%',
              height: '100%',
              animationDelay: animate ? `${delay}ms` : '0ms',
              animationDuration: animate ? '2s' : '0s',
              animationIterationCount: animate ? 'infinite' : '1'
            }}
          />
        );
      })}
    </div>
  );
};

export default TensorLogo;