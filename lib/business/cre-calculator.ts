import { PropertyType, PropertyAnalysis, MarketData } from '@/lib/supabase/types'

// Core financial calculation interfaces
export interface PropertyInputs {
  purchasePrice: number
  downPaymentPercent: number
  interestRate: number
  loanTermYears: number
  closingCostsPercent?: number
  renovationCosts?: number

  // Income
  grossRent: number
  otherIncome?: number
  vacancyRate?: number

  // Expenses
  propertyTaxesPercent?: number
  insurancePercent?: number
  maintenancePercent?: number
  managementPercent?: number
  utilitiesAnnual?: number
  otherExpensesAnnual?: number

  // Property details
  propertyType: PropertyType
  location?: {
    address?: string
    city?: string
    state?: string
    zipCode?: string
    market?: string
  }
}

export interface CalculationResults {
  // Basic financials
  loanAmount: number
  downPayment: number
  totalCashRequired: number

  // Monthly calculations
  monthlyPayment: number
  monthlyRent: number
  monthlyExpenses: number
  monthlyCashFlow: number

  // Annual calculations
  grossRentIncome: number
  effectiveGrossIncome: number
  totalOperatingExpenses: number
  netOperatingIncome: number
  annualDebtService: number
  annualCashFlow: number

  // Key metrics
  capRate: number
  cashOnCashReturn: number
  debtServiceCoverageRatio: number
  loanToValue: number
  grossRentMultiplier: number
  operatingExpenseRatio: number

  // Advanced metrics
  breakEvenRent: number
  cashBreakEven: number
  returnOnInvestment: number

  // Sensitivity analysis
  sensitivityAnalysis?: SensitivityAnalysis
}

export interface SensitivityAnalysis {
  rentChanges: Array<{ change: number; newCashFlow: number; newCashOnCash: number }>
  expenseChanges: Array<{ change: number; newCashFlow: number; newCashOnCash: number }>
  capRateChanges: Array<{ change: number; newValue: number; difference: number }>
  interestRateChanges: Array<{ change: number; newPayment: number; newCashFlow: number }>
}

export class CRECalculator {
  private static readonly MONTHS_PER_YEAR = 12
  private static readonly DEFAULT_VACANCY_RATE = 0.05 // 5%
  private static readonly DEFAULT_CLOSING_COSTS = 0.03 // 3%

  // Default expense percentages by property type
  private static readonly DEFAULT_EXPENSES = {
    office: {
      propertyTaxes: 0.015,
      insurance: 0.005,
      maintenance: 0.08,
      management: 0.05
    },
    retail: {
      propertyTaxes: 0.018,
      insurance: 0.006,
      maintenance: 0.06,
      management: 0.04
    },
    industrial: {
      propertyTaxes: 0.012,
      insurance: 0.004,
      maintenance: 0.04,
      management: 0.03
    },
    multifamily: {
      propertyTaxes: 0.012,
      insurance: 0.006,
      maintenance: 0.10,
      management: 0.06
    },
    hospitality: {
      propertyTaxes: 0.020,
      insurance: 0.008,
      maintenance: 0.12,
      management: 0.08
    },
    mixed_use: {
      propertyTaxes: 0.015,
      insurance: 0.006,
      maintenance: 0.08,
      management: 0.05
    },
    land: {
      propertyTaxes: 0.010,
      insurance: 0.002,
      maintenance: 0.02,
      management: 0.01
    },
    other: {
      propertyTaxes: 0.015,
      insurance: 0.005,
      maintenance: 0.08,
      management: 0.05
    }
  }

  /**
   * Calculate comprehensive property analysis
   */
  static calculateProperty(inputs: PropertyInputs): CalculationResults {
    // Validate inputs
    this.validateInputs(inputs)

    // Apply defaults
    const processedInputs = this.applyDefaults(inputs)

    // Basic loan calculations
    const loanAmount = processedInputs.purchasePrice * (1 - processedInputs.downPaymentPercent / 100)
    const downPayment = processedInputs.purchasePrice * (processedInputs.downPaymentPercent / 100)
    const closingCosts = processedInputs.purchasePrice * ((processedInputs.closingCostsPercent || this.DEFAULT_CLOSING_COSTS * 100) / 100)
    const totalCashRequired = downPayment + closingCosts + (processedInputs.renovationCosts || 0)

    // Monthly payment calculation
    const monthlyRate = processedInputs.interestRate / 100 / this.MONTHS_PER_YEAR
    const numberOfPayments = processedInputs.loanTermYears * this.MONTHS_PER_YEAR
    const monthlyPayment = this.calculateMonthlyPayment(loanAmount, monthlyRate, numberOfPayments)

    // Income calculations
    const monthlyRent = processedInputs.grossRent / this.MONTHS_PER_YEAR
    const grossRentIncome = processedInputs.grossRent
    const vacancyLoss = grossRentIncome * (processedInputs.vacancyRate || this.DEFAULT_VACANCY_RATE)
    const effectiveGrossIncome = grossRentIncome - vacancyLoss + (processedInputs.otherIncome || 0)

    // Expense calculations
    const expenses = this.calculateExpenses(processedInputs)
    const totalOperatingExpenses = Object.values(expenses).reduce((sum, expense) => sum + expense, 0)

    // Key calculations
    const netOperatingIncome = effectiveGrossIncome - totalOperatingExpenses
    const annualDebtService = monthlyPayment * this.MONTHS_PER_YEAR
    const annualCashFlow = netOperatingIncome - annualDebtService
    const monthlyCashFlow = annualCashFlow / this.MONTHS_PER_YEAR

    // Calculate key metrics
    const capRate = (netOperatingIncome / processedInputs.purchasePrice) * 100
    const cashOnCashReturn = (annualCashFlow / totalCashRequired) * 100
    const debtServiceCoverageRatio = netOperatingIncome / annualDebtService
    const loanToValue = (loanAmount / processedInputs.purchasePrice) * 100
    const grossRentMultiplier = processedInputs.purchasePrice / grossRentIncome
    const operatingExpenseRatio = (totalOperatingExpenses / effectiveGrossIncome) * 100

    // Advanced calculations
    const breakEvenRent = (totalOperatingExpenses + annualDebtService) / (1 - (processedInputs.vacancyRate || this.DEFAULT_VACANCY_RATE))
    const cashBreakEven = totalOperatingExpenses + annualDebtService
    const returnOnInvestment = ((netOperatingIncome - annualDebtService) / totalCashRequired) * 100

    // Sensitivity analysis
    const sensitivityAnalysis = this.performSensitivityAnalysis(processedInputs, {
      effectiveGrossIncome,
      totalOperatingExpenses,
      netOperatingIncome,
      totalCashRequired,
      annualDebtService
    })

    return {
      // Basic financials
      loanAmount,
      downPayment,
      totalCashRequired,

      // Monthly calculations
      monthlyPayment,
      monthlyRent,
      monthlyExpenses: totalOperatingExpenses / this.MONTHS_PER_YEAR,
      monthlyCashFlow,

      // Annual calculations
      grossRentIncome,
      effectiveGrossIncome,
      totalOperatingExpenses,
      netOperatingIncome,
      annualDebtService,
      annualCashFlow,

      // Key metrics
      capRate: this.roundTo(capRate, 2),
      cashOnCashReturn: this.roundTo(cashOnCashReturn, 2),
      debtServiceCoverageRatio: this.roundTo(debtServiceCoverageRatio, 2),
      loanToValue: this.roundTo(loanToValue, 2),
      grossRentMultiplier: this.roundTo(grossRentMultiplier, 2),
      operatingExpenseRatio: this.roundTo(operatingExpenseRatio, 2),

      // Advanced metrics
      breakEvenRent: this.roundTo(breakEvenRent, 0),
      cashBreakEven: this.roundTo(cashBreakEven, 0),
      returnOnInvestment: this.roundTo(returnOnInvestment, 2),

      // Sensitivity analysis
      sensitivityAnalysis
    }
  }

  /**
   * Calculate monthly mortgage payment
   */
  private static calculateMonthlyPayment(principal: number, monthlyRate: number, numberOfPayments: number): number {
    if (monthlyRate === 0) {
      return principal / numberOfPayments
    }

    return (principal * monthlyRate * Math.pow(1 + monthlyRate, numberOfPayments)) /
           (Math.pow(1 + monthlyRate, numberOfPayments) - 1)
  }

  /**
   * Calculate operating expenses
   */
  private static calculateExpenses(inputs: PropertyInputs): Record<string, number> {
    const defaults = this.DEFAULT_EXPENSES[inputs.propertyType]

    return {
      propertyTaxes: inputs.purchasePrice * ((inputs.propertyTaxesPercent || defaults.propertyTaxes * 100) / 100),
      insurance: inputs.purchasePrice * ((inputs.insurancePercent || defaults.insurance * 100) / 100),
      maintenance: inputs.grossRent * ((inputs.maintenancePercent || defaults.maintenance * 100) / 100),
      management: inputs.grossRent * ((inputs.managementPercent || defaults.management * 100) / 100),
      utilities: inputs.utilitiesAnnual || 0,
      other: inputs.otherExpensesAnnual || 0
    }
  }

  /**
   * Perform sensitivity analysis
   */
  private static performSensitivityAnalysis(
    inputs: PropertyInputs,
    baseMetrics: {
      effectiveGrossIncome: number
      totalOperatingExpenses: number
      netOperatingIncome: number
      totalCashRequired: number
      annualDebtService: number
    }
  ): SensitivityAnalysis {
    const rentChanges = [-20, -10, -5, 5, 10, 20].map(percent => {
      const newIncome = baseMetrics.effectiveGrossIncome * (1 + percent / 100)
      const newNOI = newIncome - baseMetrics.totalOperatingExpenses
      const newCashFlow = newNOI - baseMetrics.annualDebtService
      const newCashOnCash = (newCashFlow / baseMetrics.totalCashRequired) * 100

      return {
        change: percent,
        newCashFlow,
        newCashOnCash: this.roundTo(newCashOnCash, 2)
      }
    })

    const expenseChanges = [-20, -10, -5, 5, 10, 20].map(percent => {
      const newExpenses = baseMetrics.totalOperatingExpenses * (1 + percent / 100)
      const newNOI = baseMetrics.effectiveGrossIncome - newExpenses
      const newCashFlow = newNOI - baseMetrics.annualDebtService
      const newCashOnCash = (newCashFlow / baseMetrics.totalCashRequired) * 100

      return {
        change: percent,
        newCashFlow,
        newCashOnCash: this.roundTo(newCashOnCash, 2)
      }
    })

    const capRateChanges = [4, 5, 6, 7, 8, 9, 10].map(capRate => {
      const newValue = (baseMetrics.netOperatingIncome / capRate) * 100
      const difference = newValue - inputs.purchasePrice

      return {
        change: capRate,
        newValue,
        difference
      }
    })

    const interestRateChanges = [-1, -0.5, -0.25, 0.25, 0.5, 1].map(change => {
      const newRate = (inputs.interestRate + change) / 100 / this.MONTHS_PER_YEAR
      const loanAmount = inputs.purchasePrice * (1 - inputs.downPaymentPercent / 100)
      const numberOfPayments = inputs.loanTermYears * this.MONTHS_PER_YEAR
      const newPayment = this.calculateMonthlyPayment(loanAmount, newRate, numberOfPayments)
      const newAnnualDebtService = newPayment * this.MONTHS_PER_YEAR
      const newCashFlow = baseMetrics.netOperatingIncome - newAnnualDebtService

      return {
        change,
        newPayment,
        newCashFlow
      }
    })

    return {
      rentChanges,
      expenseChanges,
      capRateChanges,
      interestRateChanges
    }
  }

  /**
   * Apply default values to inputs
   */
  private static applyDefaults(inputs: PropertyInputs): PropertyInputs {
    return {
      ...inputs,
      vacancyRate: inputs.vacancyRate ?? this.DEFAULT_VACANCY_RATE,
      closingCostsPercent: inputs.closingCostsPercent ?? this.DEFAULT_CLOSING_COSTS * 100,
      otherIncome: inputs.otherIncome ?? 0,
      renovationCosts: inputs.renovationCosts ?? 0,
      utilitiesAnnual: inputs.utilitiesAnnual ?? 0,
      otherExpensesAnnual: inputs.otherExpensesAnnual ?? 0
    }
  }

  /**
   * Validate inputs
   */
  private static validateInputs(inputs: PropertyInputs): void {
    const errors: string[] = []

    if (inputs.purchasePrice <= 0) {
      errors.push('Purchase price must be greater than 0')
    }

    if (inputs.downPaymentPercent < 0 || inputs.downPaymentPercent > 100) {
      errors.push('Down payment percentage must be between 0 and 100')
    }

    if (inputs.interestRate < 0 || inputs.interestRate > 30) {
      errors.push('Interest rate must be between 0 and 30')
    }

    if (inputs.loanTermYears <= 0 || inputs.loanTermYears > 50) {
      errors.push('Loan term must be between 1 and 50 years')
    }

    if (inputs.grossRent <= 0) {
      errors.push('Gross rent must be greater than 0')
    }

    if (inputs.vacancyRate && (inputs.vacancyRate < 0 || inputs.vacancyRate > 1)) {
      errors.push('Vacancy rate must be between 0 and 1')
    }

    if (errors.length > 0) {
      throw new Error(`Validation errors: ${errors.join(', ')}`)
    }
  }

  /**
   * Round number to specified decimal places
   */
  private static roundTo(num: number, decimals: number): number {
    return Math.round(num * Math.pow(10, decimals)) / Math.pow(10, decimals)
  }

  /**
   * Calculate IRR (Internal Rate of Return) for multi-year analysis
   */
  static calculateIRR(
    initialInvestment: number,
    annualCashFlows: number[],
    terminalValue: number
  ): number {
    // Simple IRR calculation using Newton-Raphson method
    let rate = 0.1 // Starting guess of 10%
    let tolerance = 0.0001
    let maxIterations = 100

    for (let i = 0; i < maxIterations; i++) {
      let npv = -initialInvestment
      let derivative = 0

      // Calculate NPV and its derivative
      for (let year = 1; year <= annualCashFlows.length; year++) {
        const cashFlow = year === annualCashFlows.length ?
          annualCashFlows[year - 1] + terminalValue :
          annualCashFlows[year - 1]

        npv += cashFlow / Math.pow(1 + rate, year)
        derivative -= (year * cashFlow) / Math.pow(1 + rate, year + 1)
      }

      if (Math.abs(npv) < tolerance) {
        return this.roundTo(rate * 100, 2)
      }

      rate = rate - npv / derivative

      if (rate < -0.99) rate = -0.99 // Prevent infinite loops
      if (rate > 10) rate = 10
    }

    return this.roundTo(rate * 100, 2)
  }

  /**
   * Calculate NPV (Net Present Value)
   */
  static calculateNPV(
    discountRate: number,
    initialInvestment: number,
    annualCashFlows: number[],
    terminalValue: number
  ): number {
    let npv = -initialInvestment

    for (let year = 1; year <= annualCashFlows.length; year++) {
      const cashFlow = year === annualCashFlows.length ?
        annualCashFlows[year - 1] + terminalValue :
        annualCashFlows[year - 1]

      npv += cashFlow / Math.pow(1 + discountRate / 100, year)
    }

    return this.roundTo(npv, 0)
  }

  /**
   * Compare multiple properties
   */
  static compareProperties(properties: Array<{ name: string; inputs: PropertyInputs }>): Array<{
    name: string
    results: CalculationResults
    ranking: {
      capRate: number
      cashOnCash: number
      dscr: number
      overall: number
    }
  }> {
    const analyzed = properties.map(prop => ({
      name: prop.name,
      results: this.calculateProperty(prop.inputs)
    }))

    // Calculate rankings
    const withRankings = analyzed.map(prop => {
      const capRateRank = analyzed.filter(p => p.results.capRate > prop.results.capRate).length + 1
      const cashOnCashRank = analyzed.filter(p => p.results.cashOnCashReturn > prop.results.cashOnCashReturn).length + 1
      const dscrRank = analyzed.filter(p => p.results.debtServiceCoverageRatio > prop.results.debtServiceCoverageRatio).length + 1

      const overallScore = (capRateRank + cashOnCashRank + dscrRank) / 3
      const overallRank = analyzed.filter(p => {
        const otherScore = (
          analyzed.filter(x => x.results.capRate > p.results.capRate).length + 1 +
          analyzed.filter(x => x.results.cashOnCashReturn > p.results.cashOnCashReturn).length + 1 +
          analyzed.filter(x => x.results.debtServiceCoverageRatio > p.results.debtServiceCoverageRatio).length + 1
        ) / 3
        return otherScore < overallScore
      }).length + 1

      return {
        ...prop,
        ranking: {
          capRate: capRateRank,
          cashOnCash: cashOnCashRank,
          dscr: dscrRank,
          overall: overallRank
        }
      }
    })

    return withRankings.sort((a, b) => a.ranking.overall - b.ranking.overall)
  }
}