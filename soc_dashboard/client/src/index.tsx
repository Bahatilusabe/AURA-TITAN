// src/index.tsx
import React from 'react';
import ReactDOM from 'react-dom';
import './index.css';
import App from './App'; // Import App component
import { BrowserRouter as Router } from 'react-router-dom'; // Optional if you are using React Router for routing

ReactDOM.render(
  <React.StrictMode>
    <Router>
      <App />
    </Router>
  </React.StrictMode>,
  document.getElementById('root')
);
