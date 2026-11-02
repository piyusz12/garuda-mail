'use client';

import { createContext, useContext, useEffect, useState, useCallback } from 'react';

type Theme = 'light' | 'dark';

interface ThemeContextType {
  theme: Theme;
  toggleTheme: () => void;
  setTheme: (theme: Theme) => void;
}

const ThemeContext = createContext<ThemeContextType>({
  theme: 'light',
  toggleTheme: () => {},
  setTheme: () => {},
});

export function useTheme() {
  return useContext(ThemeContext);
}

function updateMetaThemeColor(theme: Theme) {
  if (typeof document === 'undefined') return;
  const color = theme === 'dark' ? '#080B11' : '#F8FAFC';
  let meta = document.querySelector('meta[name="theme-color"]:not([media])');
  if (!meta) {
    meta = document.createElement('meta');
    meta.setAttribute('name', 'theme-color');
    document.head.appendChild(meta);
  }
  meta.setAttribute('content', color);
}

export default function ThemeProvider({ children }: { children: React.ReactNode }) {
  const [theme, setThemeState] = useState<Theme>('light');
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
    let initial: Theme = 'light';
    try {
      const saved = localStorage.getItem('garuda-theme') as Theme | null;
      if (saved === 'light' || saved === 'dark') {
        initial = saved;
      }
    } catch {
      // Storage access may be blocked by browser settings or security policies
    }
    setThemeState(initial);
    document.documentElement.className = initial;
    updateMetaThemeColor(initial);
  }, []);

  const setTheme = useCallback((newTheme: Theme) => {
    setThemeState(newTheme);
    try {
      document.documentElement.className = newTheme;
      localStorage.setItem('garuda-theme', newTheme);
    } catch {
      // Handle blocked storage or quota errors gracefully
      document.documentElement.className = newTheme;
    }
    updateMetaThemeColor(newTheme);
  }, []);

  const toggleTheme = useCallback(() => {
    setTheme(theme === 'light' ? 'dark' : 'light');
  }, [theme, setTheme]);

  // Prevent flash of wrong theme
  if (!mounted) {
    return <>{children}</>;
  }

  return (
    <ThemeContext.Provider value={{ theme, toggleTheme, setTheme }}>
      {children}
    </ThemeContext.Provider>
  );
}
