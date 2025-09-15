export default function Home() {
  return (
    <main className="min-h-screen">
      <div className="container mx-auto px-4 py-16">
        <h1 className="text-4xl font-bold text-center mb-8">
          Fynsor - Where Finance Meets Intelligence
        </h1>
        <p className="text-xl text-center text-gray-600 mb-12">
          Institutional-grade commercial real estate financial modeling and analysis.
        </p>
        <div className="text-center">
          <a
            href="/contact"
            className="bg-blue-600 text-white px-8 py-3 rounded-lg hover:bg-blue-700 transition-colors"
          >
            Get Started
          </a>
        </div>
      </div>
    </main>
  )
}