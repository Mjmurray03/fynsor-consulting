import { PropertyType, MarketData } from '@/lib/supabase/types'

// Market data interfaces
export interface MarketComparables {
  propertyType: PropertyType
  market: string
  averageCapRate: number
  averageRentPsf: number
  averagePricePsf: number
  vacancyRate: number
  marketGrowth: number
  salesVolume: number
  daysOnMarket: number
  priceAppreciation: {
    oneYear: number
    threeYear: number
    fiveYear: number
  }
  lastUpdated: string
}

export interface MarketTrends {
  market: string
  propertyType: PropertyType
  trends: {
    capRates: Array<{ period: string; value: number }>
    rents: Array<{ period: string; value: number }>
    vacancy: Array<{ period: string; value: number }>
    volume: Array<{ period: string; value: number }>
  }
  forecast: {
    nextQuarter: {
      capRate: number
      rentGrowth: number
      vacancyRate: number
    }
    nextYear: {
      capRate: number
      rentGrowth: number
      vacancyRate: number
    }
  }
}

export interface SubmarketData {
  submarketName: string
  averageCapRate: number
  averageRentPsf: number
  vacancyRate: number
  majorTenants: string[]
  transportationScore: number
  amenityScore: number
  futureSupply: {
    underConstruction: number
    planned: number
    deliveryDates: string[]
  }
}

export interface DemographicData {
  market: string
  population: number
  medianIncome: number
  employmentRate: number
  majorEmployers: string[]
  populationGrowth: number
  economicDiversification: number
  educationLevel: {
    highSchool: number
    bachelors: number
    masters: number
  }
}

export class MarketAnalysis {
  // Market cap rate benchmarks by property type
  private static readonly CAP_RATE_BENCHMARKS = {
    office: {
      classA: { min: 4.5, max: 7.0, average: 5.75 },
      classB: { min: 6.0, max: 8.5, average: 7.25 },
      classC: { min: 7.5, max: 10.0, average: 8.75 }
    },
    retail: {
      regional: { min: 5.0, max: 7.5, average: 6.25 },
      community: { min: 6.0, max: 8.5, average: 7.25 },
      neighborhood: { min: 7.0, max: 9.5, average: 8.25 }
    },
    industrial: {
      distribution: { min: 4.0, max: 6.5, average: 5.25 },
      manufacturing: { min: 5.5, max: 8.0, average: 6.75 },
      flex: { min: 6.0, max: 8.5, average: 7.25 }
    },
    multifamily: {
      classA: { min: 3.5, max: 5.5, average: 4.5 },
      classB: { min: 4.5, max: 6.5, average: 5.5 },
      classC: { min: 5.5, max: 7.5, average: 6.5 }
    }
  }

  // Major US markets data (simplified - in production this would come from API)
  private static readonly MARKET_DATA: Record<string, MarketComparables> = {
    'new-york': {
      propertyType: 'office',
      market: 'New York',
      averageCapRate: 4.8,
      averageRentPsf: 65.50,
      averagePricePsf: 1365,
      vacancyRate: 0.14,
      marketGrowth: 2.1,
      salesVolume: 12500000000,
      daysOnMarket: 185,
      priceAppreciation: { oneYear: 1.2, threeYear: 8.5, fiveYear: 18.3 },
      lastUpdated: new Date().toISOString()
    },
    'los-angeles': {
      propertyType: 'office',
      market: 'Los Angeles',
      averageCapRate: 5.2,
      averageRentPsf: 42.75,
      averagePricePsf: 822,
      vacancyRate: 0.16,
      marketGrowth: 1.8,
      salesVolume: 8200000000,
      daysOnMarket: 165,
      priceAppreciation: { oneYear: 2.8, threeYear: 12.1, fiveYear: 28.4 },
      lastUpdated: new Date().toISOString()
    },
    'chicago': {
      propertyType: 'office',
      market: 'Chicago',
      averageCapRate: 6.1,
      averageRentPsf: 32.25,
      averagePricePsf: 528,
      vacancyRate: 0.15,
      marketGrowth: 1.2,
      salesVolume: 4100000000,
      daysOnMarket: 195,
      priceAppreciation: { oneYear: 0.8, threeYear: 5.2, fiveYear: 12.8 },
      lastUpdated: new Date().toISOString()
    }
  }

  /**
   * Get market comparables for a specific property type and market
   */
  static getMarketComparables(
    propertyType: PropertyType,
    market: string
  ): MarketComparables | null {
    const marketKey = market.toLowerCase().replace(/\s+/g, '-')
    const data = this.MARKET_DATA[marketKey]

    if (!data) {
      return null
    }

    // Adjust data based on property type
    return {
      ...data,
      propertyType,
      averageCapRate: this.adjustCapRateForPropertyType(data.averageCapRate, propertyType),
      averageRentPsf: this.adjustRentForPropertyType(data.averageRentPsf, propertyType),
      averagePricePsf: this.adjustPriceForPropertyType(data.averagePricePsf, propertyType)
    }
  }

  /**
   * Analyze property performance against market
   */
  static analyzeAgainstMarket(
    propertyCapRate: number,
    propertyRentPsf: number,
    propertyType: PropertyType,
    market: string
  ): {
    marketComparison: {
      capRatePosition: 'above' | 'below' | 'at' // compared to market average
      rentPosition: 'above' | 'below' | 'at'
      capRateDifference: number // percentage points
      rentDifference: number // percentage
    }
    recommendations: string[]
    riskAssessment: {
      level: 'low' | 'medium' | 'high'
      factors: string[]
      score: number // 1-100
    }
  } {
    const marketData = this.getMarketComparables(propertyType, market)

    if (!marketData) {
      return {
        marketComparison: {
          capRatePosition: 'at',
          rentPosition: 'at',
          capRateDifference: 0,
          rentDifference: 0
        },
        recommendations: ['Market data not available for comparison'],
        riskAssessment: {
          level: 'medium',
          factors: ['Unknown market conditions'],
          score: 50
        }
      }
    }

    const capRateDifference = propertyCapRate - marketData.averageCapRate
    const rentDifference = ((propertyRentPsf - marketData.averageRentPsf) / marketData.averageRentPsf) * 100

    const capRatePosition = Math.abs(capRateDifference) < 0.25 ? 'at' :
                           capRateDifference > 0 ? 'above' : 'below'
    const rentPosition = Math.abs(rentDifference) < 5 ? 'at' :
                        rentDifference > 0 ? 'above' : 'below'

    // Generate recommendations
    const recommendations = this.generateRecommendations(
      capRatePosition,
      rentPosition,
      capRateDifference,
      rentDifference,
      marketData
    )

    // Assess risk
    const riskAssessment = this.assessMarketRisk(
      propertyCapRate,
      propertyRentPsf,
      marketData
    )

    return {
      marketComparison: {
        capRatePosition,
        rentPosition,
        capRateDifference: Math.round(capRateDifference * 100) / 100,
        rentDifference: Math.round(rentDifference * 100) / 100
      },
      recommendations,
      riskAssessment
    }
  }

  /**
   * Get market trends for forecasting
   */
  static getMarketTrends(
    propertyType: PropertyType,
    market: string
  ): MarketTrends | null {
    // This would typically fetch from a real market data API
    // For demo purposes, we'll generate sample trends

    const marketData = this.getMarketComparables(propertyType, market)
    if (!marketData) return null

    // Generate sample historical trends (last 8 quarters)
    const periods = []
    for (let i = 7; i >= 0; i--) {
      const date = new Date()
      date.setMonth(date.getMonth() - (i * 3))
      periods.push(`${date.getFullYear()}Q${Math.floor(date.getMonth() / 3) + 1}`)
    }

    const baseCapRate = marketData.averageCapRate
    const baseRent = marketData.averageRentPsf
    const baseVacancy = marketData.vacancyRate

    return {
      market,
      propertyType,
      trends: {
        capRates: periods.map((period, index) => ({
          period,
          value: baseCapRate + (Math.random() - 0.5) * 0.5 + (index * 0.05)
        })),
        rents: periods.map((period, index) => ({
          period,
          value: baseRent * (1 + index * 0.01 + (Math.random() - 0.5) * 0.02)
        })),
        vacancy: periods.map((period, index) => ({
          period,
          value: Math.max(0.02, baseVacancy + (Math.random() - 0.5) * 0.03)
        })),
        volume: periods.map((period, index) => ({
          period,
          value: marketData.salesVolume * (0.8 + Math.random() * 0.4)
        }))
      },
      forecast: {
        nextQuarter: {
          capRate: baseCapRate + 0.1,
          rentGrowth: 2.5,
          vacancyRate: baseVacancy - 0.005
        },
        nextYear: {
          capRate: baseCapRate + 0.3,
          rentGrowth: 3.2,
          vacancyRate: baseVacancy - 0.01
        }
      }
    }
  }

  /**
   * Calculate market risk score
   */
  static calculateMarketRiskScore(
    market: string,
    propertyType: PropertyType
  ): {
    totalScore: number
    factors: {
      liquidity: number
      volatility: number
      growth: number
      supply: number
      demand: number
    }
    interpretation: string
  } {
    const marketData = this.getMarketComparables(propertyType, market)

    if (!marketData) {
      return {
        totalScore: 50,
        factors: { liquidity: 50, volatility: 50, growth: 50, supply: 50, demand: 50 },
        interpretation: 'Insufficient market data for analysis'
      }
    }

    // Calculate individual risk factors (0-100, where 0 is highest risk)
    const factors = {
      liquidity: Math.min(100, Math.max(0, (marketData.salesVolume / 1000000000) * 10)),
      volatility: Math.min(100, Math.max(0, 100 - (marketData.vacancyRate * 1000))),
      growth: Math.min(100, Math.max(0, marketData.marketGrowth * 20)),
      supply: Math.min(100, Math.max(0, 100 - (marketData.daysOnMarket / 5))),
      demand: Math.min(100, Math.max(0, (1 - marketData.vacancyRate) * 100))
    }

    const totalScore = Object.values(factors).reduce((sum, score) => sum + score, 0) / 5

    let interpretation = ''
    if (totalScore >= 75) {
      interpretation = 'Low risk market with strong fundamentals'
    } else if (totalScore >= 50) {
      interpretation = 'Moderate risk market with mixed indicators'
    } else if (totalScore >= 25) {
      interpretation = 'High risk market with concerning metrics'
    } else {
      interpretation = 'Very high risk market - proceed with extreme caution'
    }

    return {
      totalScore: Math.round(totalScore),
      factors: Object.fromEntries(
        Object.entries(factors).map(([key, value]) => [key, Math.round(value)])
      ) as typeof factors,
      interpretation
    }
  }

  // Private helper methods

  private static adjustCapRateForPropertyType(baseCapRate: number, propertyType: PropertyType): number {
    const adjustments = {
      office: 0,
      retail: 0.5,
      industrial: -0.5,
      multifamily: -1.0,
      hospitality: 1.5,
      mixed_use: 0.25,
      land: 2.0,
      other: 0
    }

    return baseCapRate + (adjustments[propertyType] || 0)
  }

  private static adjustRentForPropertyType(baseRent: number, propertyType: PropertyType): number {
    const multipliers = {
      office: 1.0,
      retail: 0.8,
      industrial: 0.4,
      multifamily: 0.6,
      hospitality: 1.2,
      mixed_use: 0.9,
      land: 0.1,
      other: 1.0
    }

    return baseRent * (multipliers[propertyType] || 1.0)
  }

  private static adjustPriceForPropertyType(basePrice: number, propertyType: PropertyType): number {
    const multipliers = {
      office: 1.0,
      retail: 0.7,
      industrial: 0.3,
      multifamily: 0.8,
      hospitality: 1.1,
      mixed_use: 0.85,
      land: 0.2,
      other: 1.0
    }

    return basePrice * (multipliers[propertyType] || 1.0)
  }

  private static generateRecommendations(
    capRatePosition: 'above' | 'below' | 'at',
    rentPosition: 'above' | 'below' | 'at',
    capRateDifference: number,
    rentDifference: number,
    marketData: MarketComparables
  ): string[] {
    const recommendations: string[] = []

    if (capRatePosition === 'above' && capRateDifference > 1) {
      recommendations.push('Cap rate significantly above market - verify property condition and rental income')
    } else if (capRatePosition === 'below' && capRateDifference < -1) {
      recommendations.push('Cap rate below market - ensure property justifies premium pricing')
    }

    if (rentPosition === 'below' && rentDifference < -10) {
      recommendations.push('Rents below market - potential for rent increases or property improvements')
    } else if (rentPosition === 'above' && rentDifference > 15) {
      recommendations.push('Rents above market - monitor for tenant retention risks')
    }

    if (marketData.vacancyRate > 0.15) {
      recommendations.push('High market vacancy - consider tenant retention strategies')
    }

    if (marketData.marketGrowth < 1) {
      recommendations.push('Slow market growth - focus on properties with value-add opportunities')
    }

    if (recommendations.length === 0) {
      recommendations.push('Property metrics align well with market conditions')
    }

    return recommendations
  }

  private static assessMarketRisk(
    propertyCapRate: number,
    propertyRentPsf: number,
    marketData: MarketComparables
  ): {
    level: 'low' | 'medium' | 'high'
    factors: string[]
    score: number
  } {
    const factors: string[] = []
    let riskScore = 0

    // Cap rate risk
    const capRateDiff = Math.abs(propertyCapRate - marketData.averageCapRate)
    if (capRateDiff > 2) {
      factors.push('Property cap rate significantly different from market')
      riskScore += 25
    } else if (capRateDiff > 1) {
      riskScore += 10
    }

    // Market conditions risk
    if (marketData.vacancyRate > 0.15) {
      factors.push('High market vacancy rate')
      riskScore += 20
    } else if (marketData.vacancyRate > 0.10) {
      riskScore += 10
    }

    if (marketData.marketGrowth < 0) {
      factors.push('Negative market growth')
      riskScore += 30
    } else if (marketData.marketGrowth < 1) {
      factors.push('Slow market growth')
      riskScore += 15
    }

    // Liquidity risk
    if (marketData.daysOnMarket > 200) {
      factors.push('Extended time to sell in market')
      riskScore += 15
    }

    // Determine risk level
    let level: 'low' | 'medium' | 'high'
    if (riskScore <= 20) {
      level = 'low'
    } else if (riskScore <= 50) {
      level = 'medium'
    } else {
      level = 'high'
    }

    if (factors.length === 0) {
      factors.push('Market conditions appear stable')
    }

    return {
      level,
      factors,
      score: Math.min(100, riskScore)
    }
  }
}