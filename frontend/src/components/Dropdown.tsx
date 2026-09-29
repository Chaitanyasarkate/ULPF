import { useState, useRef, useEffect, ReactNode } from 'react';
import { ChevronDown } from 'lucide-react';

export interface DropdownItem {
  label: string;
  icon?: ReactNode;
  onClick: () => void;
  variant?: 'default' | 'destructive';
  disabled?: boolean;
}

interface DropdownProps {
  items: DropdownItem[];
  triggerLabel?: string;
  triggerIcon?: ReactNode;
  align?: 'left' | 'right';
}

export function Dropdown({ items, triggerLabel, triggerIcon, align = 'right' }: DropdownProps) {
  const [isOpen, setIsOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  return (
    <div className="relative" ref={dropdownRef}>
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="flex items-center gap-2 px-3 py-2 text-sm font-medium text-gray-300 hover:text-white rounded-lg hover:bg-dark-200 transition-colors"
        aria-haspopup="true"
        aria-expanded={isOpen}
      >
        {triggerIcon && <span className="w-4 h-4">{triggerIcon}</span>}
        {triggerLabel}
        <ChevronDown className={`w-4 h-4 transition-transform ${isOpen ? 'rotate-180' : ''}`} />
      </button>

      {isOpen && (
        <div
          className={`absolute z-50 mt-1 min-w-[180px] bg-dark-100 border border-gray-700 rounded-lg shadow-lg overflow-hidden ${align === 'right' ? 'right-0' : 'left-0'}`}
          role="menu"
        >
          {items.map((item, index) => (
            <button
              key={index}
              onClick={() => {
                if (!item.disabled) {
                  item.onClick();
                  setIsOpen(false);
                }
              }}
              disabled={item.disabled}
              className={`w-full flex items-center gap-2 px-4 py-2 text-sm text-left transition-colors ${
                item.variant === 'destructive'
                  ? 'text-red-400 hover:bg-red-900/30'
                  : 'text-gray-300 hover:text-white hover:bg-dark-200'
              } ${item.disabled ? 'opacity-50 cursor-not-allowed' : ''}`}
              role="menuitem"
            >
              {item.icon && <span className="w-4 h-4">{item.icon}</span>}
              {item.label}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}