import { useState } from 'react'
import reactLogo from './assets/react.svg'
import viteLogo from '/vite.svg'
import './App.css'
import MonitoringDashboard from "./MonitoringDashboard"

function App() {
  const [count, setCount] = useState(0)

  return <MonitoringDashboard />
}

export default App
