import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';

const root = document.getElementById('root');
if (!root) throw new Error('Missing console root');

// AUTH-T01 validates the toolchain only. The first screen belongs to AUTH-T08.
createRoot(root).render(<StrictMode>{null}</StrictMode>);
