import { Outlet } from 'react-router-dom'
import Footer from './Footer'
import Navbar from './Navbar'

export default function Layout() {
  return (
    <div className="min-h-screen flex flex-col bg-vault-bg">
      <Navbar />
      <main className="flex-1 mt-14 mb-10 px-4 py-4 w-full">
        <Outlet />
      </main>
      <Footer />
    </div>
  )
}
