import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { AuthConsole } from './authentication/AuthConsole';
import './styles.css';
import './user-management/styles.css';
import './dashboard/styles.css';
import { captureInvitation } from './user-management/client';

captureInvitation();

const root = document.getElementById('root');
if (!root) throw new Error('Missing console root');

createRoot(root).render(<StrictMode><AuthConsole /></StrictMode>);
