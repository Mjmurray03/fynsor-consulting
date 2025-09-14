# Fynsor Branding Components

## Logo Implementation Guide

The Fynsor brand uses a distinctive tensor-based logo system with multiple implementation options.

### TensorLogo Component

**Location**: `components/animations/TensorLogo.tsx`

#### Props
- `size?: number` - Logo size in pixels (default: 32)
- `animate?: boolean` - Enable pulse animation (default: false)
- `className?: string` - Additional CSS classes
- `variant?: 'image' | 'dots' | 'auto'` - Display mode (default: 'auto')

#### Variants

1. **Image Variant** (`variant="image"`)
   - Uses uploaded logo file: `/public/images/logo.png`
   - Best for larger sizes (64px+)
   - High quality with full design details
   - Automatic fallback to dots if image fails

2. **Dots Variant** (`variant="dots"`)
   - Algorithmic 4x4 grid pattern
   - Perfect for small sizes (32px and below)
   - Fast rendering, no image dependencies
   - Forms distinctive "F" pattern

3. **Auto Variant** (`variant="auto"`) - Default
   - Automatically chooses best variant based on size
   - Image for sizes ≥64px, dots for smaller sizes
   - Optimal performance and quality balance

#### Usage Examples

```tsx
// Navigation logo (small, using image)
<TensorLogo size={32} variant="image" />

// Hero logo (large, animated)
<TensorLogo size={120} animate variant="auto" />

// Footer logo (small, dots pattern)
<TensorLogo size={24} variant="dots" />

// Contact page (very large, high quality)
<TensorLogo size={200} animate variant="image" />
```

### LogoBanner Component

**Location**: `components/branding/LogoBanner.tsx`

#### Props
- `width?: number` - Banner width (default: 800)
- `height?: number` - Banner height (default: 200)
- `className?: string` - Additional CSS classes
- `variant?: 'banner' | 'cover'` - Image type
- `animate?: boolean` - Enable fade-in animation

#### Variants

1. **Banner** (`variant="banner"`)
   - Uses: `/public/images/banner.png`
   - LinkedIn banner format with grid background
   - Professional presentation layout

2. **Cover** (`variant="cover"`)
   - Uses: `/public/images/cover.png`
   - Universal cover design
   - Versatile for multiple contexts

#### Usage Examples

```tsx
// Page header banner
<LogoBanner width={1200} height={300} variant="banner" animate />

// About page cover
<LogoBanner width={800} height={400} variant="cover" />
```

## Brand Guidelines

### Colors
- **Primary Black**: `#000000`
- **Border Gray**: `#666666`
- **White**: `#FFFFFF`

### Logo Pattern (4x4 Grid)
```
[●] [●] [●] [●]  ← Top horizontal
[●] [ ] [ ] [ ]  ← Left vertical
[●] [●] [●] [ ]  ← Middle horizontal
[●] [ ] [ ] [ ]  ← Bottom vertical
```

### Animation Guidelines
- **Subtle animations only** - maintain professional appearance
- **2-3 second duration** for pulse effects
- **Hover effects** - slight elevation and shadow enhancement
- **Load animations** - fade-in for brand introduction

### Responsive Behavior
- **Mobile**: 24-32px logos
- **Desktop**: 32-48px navigation logos
- **Hero sections**: 80-200px featured logos
- **Always maintain aspect ratio**

### Performance Optimization
- **Automatic variant selection** optimizes for size
- **Image priority loading** for large, above-fold logos
- **CSS animations** preferred over JavaScript for smoothness
- **WebP support** through Next.js Image component

## File Structure

```
public/images/
├── logo.png      - 1024x1024 square logo with tensor pattern
├── banner.png    - LinkedIn banner with grid background
└── cover.png     - Universal cover design

components/branding/
├── LogoBanner.tsx        - Banner component
└── README.md            - This documentation

components/animations/
└── TensorLogo.tsx       - Main logo component
```

## Integration Points

### Navigation
- Uses 32px image variant in header
- Hover effects enabled
- Links to homepage

### Page Headers
- Large animated logos (80-200px)
- Auto variant selection
- Fade-in animations

### Contact Form
- 200px animated logo on right side
- Image variant for maximum quality
- Continuous pulse animation

### About Page
- Multiple logo sizes throughout
- Tensor pattern explanation
- Brand story integration

## Accessibility

- **Alt text**: "Fynsor Consulting - Tensor Logo"
- **Semantic markup** with proper heading hierarchy
- **High contrast** - black/white/gray only
- **Scalable** - works at all sizes without quality loss
- **Keyboard navigation** support through Next.js Link integration

## Technical Notes

- Uses Next.js `Image` component for optimization
- Automatic WebP conversion in production
- Priority loading for above-fold logos
- Error handling with graceful fallbacks
- CSS-only animations for best performance