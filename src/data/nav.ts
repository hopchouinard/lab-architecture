export type NavItem = { key: string; label: string; href: string; group?: string };

export const NAV: NavItem[] = [
  { key: "overview", label: "Overview", href: "/" },
  { key: "thesis", label: "The Thesis", href: "/thesis" },
  { key: "explorer", label: "The Explorer", href: "/explorer" },
  { key: "describe", label: "Describe", href: "/describe", group: "The three boundaries" },
  { key: "operate", label: "Operate", href: "/operate", group: "The three boundaries" },
  { key: "publish", label: "Publish", href: "/publish", group: "The three boundaries" },
];
