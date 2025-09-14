# Fynsor - Where Finance Meets Intelligence

A sophisticated commercial real estate analysis platform built with Next.js 14, TypeScript, and Tailwind CSS.

## Project Structure

```
fynsor-consulting/
├── app/                     # Next.js App Router
│   ├── about/page.tsx      # About page explaining Fynsor name and standards
│   ├── contact/page.tsx    # Contact page with split layout
│   ├── insights/page.tsx   # Insights page (coming soon)
│   ├── services/page.tsx   # Services page with CRE property types
│   ├── globals.css         # Global styles and Tailwind imports
│   ├── layout.tsx          # Root layout with Inter font
│   └── page.tsx            # Homepage with animated tensor logo
├── components/
│   ├── animations/
│   │   └── TensorLogo.tsx  # 4x4 grid tensor logo with F pattern
│   ├── layout/
│   │   └── Layout.tsx      # Main layout wrapper
│   ├── navigation/
│   │   └── Navigation.tsx  # Black navigation with sticky positioning
│   └── ui/
│       └── Section.tsx     # Reusable section component
├── next.config.js          # Next.js configuration
├── package.json            # Dependencies and scripts
├── postcss.config.js       # PostCSS configuration
├── tailwind.config.js      # Tailwind CSS configuration
└── tsconfig.json           # TypeScript configuration
```

## Design System

### Colors
- **Black**: #000000 (primary text, navigation background)
- **White**: #FFFFFF (backgrounds, logo dots)
- **Gray**: #666666 (borders, secondary elements)

### Typography
- **Font**: Inter (Google Fonts)
- **System Fallback**: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif

### Components

#### TensorLogo
- 4x4 grid with gray border (#666666)
- White dots forming an "F" pattern
- Optional pulse animation for sequential dot appearance
- Configurable size and animation state

#### Navigation
- Fixed/sticky positioning with backdrop blur
- Black background (#000000)
- Tensor logo on the left
- Menu items: About, Services, Insights, Contact
- Responsive mobile menu

#### Layout System
- Section component for consistent spacing
- Responsive container with max-width constraints
- Mobile-first design approach

## Key Features

### Homepage
- Animated tensor logo with sequential dot animation
- "Where Finance Meets Intelligence" tagline
- Fade-in animations with staggered delays
- Three-column value proposition section

### About Page
- Explanation of Fynsor name (Finance + Tensor)
- Institutional standards section
- Mission statement
- Professional grid patterns

### Services Page
- Six major CRE property types with features
- Financial modeling capabilities
- Advanced analytics framework
- Tensor-based computations explanation

### Contact Page
- Split layout: form on left, logo on right
- Professional contact form with validation
- Direct contact information
- Security and confidentiality assurances

## Development

### Getting Started
```bash
npm install
npm run dev
```

### Building for Production
```bash
npm run build
npm start
```

### Styling Guidelines
- Use only approved colors: #000000, #FFFFFF, #666666
- No gradients or shadows
- Clean, minimal design with professional spacing
- Mobile-first responsive design
- Institutional-grade quality

## Branding

**Fynsor** represents the fusion of:
- **Fyn** (Finance) - Deep expertise in financial analysis and institutional standards
- **Sor** (Tensor) - Advanced mathematical frameworks and computational intelligence

The tensor logo's 4x4 grid forming an "F" pattern symbolizes the intersection of traditional finance with modern computational methods.