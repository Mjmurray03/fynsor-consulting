import { createHash } from 'crypto';
import { encryptionManager } from './encryption.config';
import { dataProtectionManager, AuditLog } from './data-protection';

export interface ComplianceConfig {
  soc2: {
    enabled: boolean;
    type: 'type1' | 'type2';
    reportingPeriod: number; // days
    controls: SOC2Control[];
    auditFrequency: number; // days
  };
  frameworks: {
    iso27001: boolean;
    nist: boolean;
    pci: boolean;
    hipaa: boolean;
  };
  reporting: {
    automated: boolean;
    frequency: 'daily' | 'weekly' | 'monthly' | 'quarterly';
    recipients: string[];
    encryptReports: boolean;
  };
  monitoring: {
    realTime: boolean;
    alertThresholds: AlertThreshold[];
    escalationRules: EscalationRule[];
  };
}

export interface SOC2Control {
  id: string;
  category: 'CC' | 'A' | 'PI' | 'P' | 'C'; // Common Criteria, Availability, Processing Integrity, Privacy, Confidentiality
  number: string;
  title: string;
  description: string;
  testProcedure: string;
  frequency: 'continuous' | 'daily' | 'weekly' | 'monthly' | 'quarterly';
  automated: boolean;
  responsible: string;
  evidence: string[];
}

export interface AlertThreshold {
  metric: string;
  operator: '>' | '<' | '=' | '>=' | '<=';
  value: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
  cooldown: number; // minutes
}

export interface EscalationRule {
  severity: 'low' | 'medium' | 'high' | 'critical';
  timeToEscalate: number; // minutes
  recipients: string[];
  methods: ('email' | 'sms' | 'slack' | 'webhook')[];
}

export interface ComplianceIncident {
  id: string;
  type: 'security' | 'privacy' | 'availability' | 'integrity' | 'confidentiality';
  severity: 'low' | 'medium' | 'high' | 'critical';
  status: 'open' | 'investigating' | 'resolved' | 'closed';
  title: string;
  description: string;
  detectedAt: Date;
  acknowledgedAt?: Date;
  resolvedAt?: Date;
  assignedTo: string;
  affectedSystems: string[];
  rootCause?: string;
  remediation?: string;
  preventiveMeasures?: string[];
  evidence: string[];
  notificationsSent: boolean;
}

export interface ComplianceReport {
  id: string;
  type: 'soc2' | 'gdpr' | 'ccpa' | 'custom';
  period: {
    start: Date;
    end: Date;
  };
  generatedAt: Date;
  generatedBy: string;
  summary: {
    totalControls: number;
    passedControls: number;
    failedControls: number;
    complianceScore: number;
  };
  findings: ComplianceFinding[];
  recommendations: string[];
  attachments: string[];
  encrypted: boolean;
}

export interface ComplianceFinding {
  id: string;
  controlId: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  status: 'pass' | 'fail' | 'exception' | 'not_tested';
  description: string;
  evidence: string[];
  remediation?: string;
  dueDate?: Date;
  responsible?: string;
}

export interface RiskAssessment {
  id: string;
  asset: string;
  threat: string;
  vulnerability: string;
  likelihood: 'very_low' | 'low' | 'medium' | 'high' | 'very_high';
  impact: 'very_low' | 'low' | 'medium' | 'high' | 'very_high';
  riskScore: number;
  mitigation: string[];
  residualRisk: number;
  owner: string;
  reviewDate: Date;
}

export const COMPLIANCE_CONFIG: ComplianceConfig = {
  soc2: {
    enabled: process.env.SOC2_ENABLED !== 'false',
    type: (process.env.SOC2_TYPE as 'type1' | 'type2') || 'type2',
    reportingPeriod: parseInt(process.env.SOC2_REPORTING_PERIOD || '365'),
    controls: [], // Will be populated with actual SOC 2 controls
    auditFrequency: parseInt(process.env.SOC2_AUDIT_FREQUENCY || '365')
  },
  frameworks: {
    iso27001: process.env.ISO27001_ENABLED === 'true',
    nist: process.env.NIST_ENABLED === 'true',
    pci: process.env.PCI_ENABLED === 'true',
    hipaa: process.env.HIPAA_ENABLED === 'true'
  },
  reporting: {
    automated: process.env.AUTOMATED_REPORTING !== 'false',
    frequency: (process.env.REPORTING_FREQUENCY as any) || 'monthly',
    recipients: (process.env.COMPLIANCE_REPORT_RECIPIENTS || '').split(',').filter(Boolean),
    encryptReports: process.env.ENCRYPT_COMPLIANCE_REPORTS !== 'false'
  },
  monitoring: {
    realTime: process.env.REALTIME_MONITORING !== 'false',
    alertThresholds: [
      { metric: 'failed_logins', operator: '>', value: 5, severity: 'medium', cooldown: 15 },
      { metric: 'data_access_anomaly', operator: '>', value: 10, severity: 'high', cooldown: 5 },
      { metric: 'encryption_failures', operator: '>', value: 1, severity: 'critical', cooldown: 1 },
      { metric: 'unauthorized_access_attempts', operator: '>', value: 3, severity: 'high', cooldown: 10 }
    ],
    escalationRules: [
      { severity: 'low', timeToEscalate: 240, recipients: ['security@fynsor.com'], methods: ['email'] },
      { severity: 'medium', timeToEscalate: 60, recipients: ['security@fynsor.com', 'ops@fynsor.com'], methods: ['email', 'slack'] },
      { severity: 'high', timeToEscalate: 15, recipients: ['security@fynsor.com', 'ciso@fynsor.com'], methods: ['email', 'sms', 'slack'] },
      { severity: 'critical', timeToEscalate: 5, recipients: ['security@fynsor.com', 'ciso@fynsor.com', 'ceo@fynsor.com'], methods: ['email', 'sms', 'slack', 'webhook'] }
    ]
  }
};

export const SOC2_CONTROLS: SOC2Control[] = [
  {
    id: 'CC1.1',
    category: 'CC',
    number: '1.1',
    title: 'Control Environment - Commitment to Integrity and Ethical Values',
    description: 'The entity demonstrates a commitment to integrity and ethical values.',
    testProcedure: 'Review code of conduct, ethics training, and incident reporting procedures',
    frequency: 'quarterly',
    automated: false,
    responsible: 'Chief Compliance Officer',
    evidence: ['code_of_conduct.pdf', 'ethics_training_records.xlsx', 'incident_reports.json']
  },
  {
    id: 'CC2.1',
    category: 'CC',
    number: '2.1',
    title: 'Communication and Information - Quality of Information',
    description: 'The entity obtains or generates and uses relevant, quality information to support the functioning of internal control.',
    testProcedure: 'Review data quality controls and information management procedures',
    frequency: 'monthly',
    automated: true,
    responsible: 'Data Protection Officer',
    evidence: ['data_quality_reports.json', 'information_lifecycle_policy.pdf']
  },
  {
    id: 'CC3.1',
    category: 'CC',
    number: '3.1',
    title: 'Risk Assessment - Specifies Suitable Objectives',
    description: 'The entity specifies objectives with sufficient clarity to enable the identification and assessment of risks.',
    testProcedure: 'Review risk management framework and risk assessment procedures',
    frequency: 'quarterly',
    automated: false,
    responsible: 'Chief Risk Officer',
    evidence: ['risk_management_policy.pdf', 'risk_assessments.json']
  },
  {
    id: 'CC4.1',
    category: 'CC',
    number: '4.1',
    title: 'Monitoring Activities - Ongoing and Separate Evaluations',
    description: 'The entity selects, develops, and performs ongoing and/or separate evaluations to ascertain whether the components of internal control are present and functioning.',
    testProcedure: 'Review monitoring procedures and control testing results',
    frequency: 'continuous',
    automated: true,
    responsible: 'Internal Audit',
    evidence: ['monitoring_logs.json', 'control_test_results.xlsx']
  },
  {
    id: 'CC5.1',
    category: 'CC',
    number: '5.1',
    title: 'Control Activities - Selects and Develops Control Activities',
    description: 'The entity selects and develops control activities that contribute to the mitigation of risks to the achievement of objectives to acceptable levels.',
    testProcedure: 'Review control design and implementation evidence',
    frequency: 'monthly',
    automated: true,
    responsible: 'Security Team',
    evidence: ['control_matrix.xlsx', 'implementation_evidence.json']
  },
  {
    id: 'CC6.1',
    category: 'CC',
    number: '6.1',
    title: 'Logical and Physical Access Controls - Restricts Logical Access',
    description: 'The entity implements logical access security software, infrastructure, and architectures over protected information assets to protect them from security events.',
    testProcedure: 'Test access controls, authentication mechanisms, and authorization procedures',
    frequency: 'continuous',
    automated: true,
    responsible: 'IT Security Team',
    evidence: ['access_control_logs.json', 'authentication_reports.json', 'authorization_matrix.xlsx']
  },
  {
    id: 'CC7.1',
    category: 'CC',
    number: '7.1',
    title: 'System Operations - Manages System Capacity',
    description: 'To meet its objectives, the entity uses detection and monitoring procedures to identify system capacity issues.',
    testProcedure: 'Review system monitoring, capacity planning, and performance management',
    frequency: 'continuous',
    automated: true,
    responsible: 'Operations Team',
    evidence: ['capacity_reports.json', 'performance_metrics.json', 'monitoring_alerts.json']
  },
  {
    id: 'CC8.1',
    category: 'CC',
    number: '8.1',
    title: 'Change Management - Manages Changes',
    description: 'The entity authorizes, designs, develops or acquires, configures, documents, tests, approves, and implements changes to infrastructure, data, software, and procedures.',
    testProcedure: 'Review change management procedures and change approval records',
    frequency: 'continuous',
    automated: true,
    responsible: 'Change Management Board',
    evidence: ['change_requests.json', 'approval_records.xlsx', 'deployment_logs.json']
  }
];

export class ComplianceManager {
  private static instance: ComplianceManager;
  private incidents: Map<string, ComplianceIncident> = new Map();
  private reports: Map<string, ComplianceReport> = new Map();
  private findings: Map<string, ComplianceFinding> = new Map();
  private riskAssessments: Map<string, RiskAssessment> = new Map();
  private monitoringInterval: NodeJS.Timeout;
  private alertCooldowns: Map<string, number> = new Map();

  private constructor() {
    this.initializeControls();
    this.startMonitoring();
  }

  public static getInstance(): ComplianceManager {
    if (!ComplianceManager.instance) {
      ComplianceManager.instance = new ComplianceManager();
    }
    return ComplianceManager.instance;
  }

  public async createIncident(incident: Omit<ComplianceIncident, 'id' | 'detectedAt' | 'notificationsSent'>): Promise<ComplianceIncident> {
    const fullIncident: ComplianceIncident = {
      ...incident,
      id: this.generateIncidentId(),
      detectedAt: new Date(),
      notificationsSent: false
    };

    this.incidents.set(fullIncident.id, fullIncident);
    
    // Log incident creation
    await dataProtectionManager.logDataAccess(
      fullIncident.assignedTo,
      'INCIDENT_CREATED',
      'compliance_incident',
      fullIncident.id,
      fullIncident.severity as any
    );

    // Send notifications based on severity
    await this.sendIncidentNotifications(fullIncident);

    return fullIncident;
  }

  public async updateIncident(incidentId: string, updates: Partial<ComplianceIncident>): Promise<ComplianceIncident | null> {
    const incident = this.incidents.get(incidentId);
    if (!incident) {
      return null;
    }

    const updatedIncident = { ...incident, ...updates };
    this.incidents.set(incidentId, updatedIncident);

    await dataProtectionManager.logDataAccess(
      updatedIncident.assignedTo,
      'INCIDENT_UPDATED',
      'compliance_incident',
      incidentId,
      'medium'
    );

    return updatedIncident;
  }

  public async generateComplianceReport(type: ComplianceReport['type'], period: { start: Date; end: Date }, generatedBy: string): Promise<ComplianceReport> {
    const reportId = this.generateReportId();
    const controls = this.getControlsForReportType(type);
    
    const findings = this.generateFindings(controls, period);
    const passedControls = findings.filter(f => f.status === 'pass').length;
    const failedControls = findings.filter(f => f.status === 'fail').length;
    const complianceScore = (passedControls / controls.length) * 100;

    const report: ComplianceReport = {
      id: reportId,
      type,
      period,
      generatedAt: new Date(),
      generatedBy,
      summary: {
        totalControls: controls.length,
        passedControls,
        failedControls,
        complianceScore
      },
      findings,
      recommendations: this.generateRecommendations(findings),
      attachments: [],
      encrypted: COMPLIANCE_CONFIG.reporting.encryptReports
    };

    this.reports.set(reportId, report);

    await dataProtectionManager.logDataAccess(
      generatedBy,
      'COMPLIANCE_REPORT_GENERATED',
      'compliance_report',
      reportId,
      'medium'
    );

    return report;
  }

  public async conductRiskAssessment(assessment: Omit<RiskAssessment, 'id' | 'riskScore' | 'residualRisk'>): Promise<RiskAssessment> {
    const riskScore = this.calculateRiskScore(assessment.likelihood, assessment.impact);
    const residualRisk = this.calculateResidualRisk(riskScore, assessment.mitigation);

    const fullAssessment: RiskAssessment = {
      ...assessment,
      id: this.generateRiskAssessmentId(),
      riskScore,
      residualRisk
    };

    this.riskAssessments.set(fullAssessment.id, fullAssessment);

    await dataProtectionManager.logDataAccess(
      assessment.owner,
      'RISK_ASSESSMENT_CONDUCTED',
      'risk_assessment',
      fullAssessment.id,
      this.getRiskSeverity(riskScore)
    );

    return fullAssessment;
  }

  public async testControl(controlId: string, testData: any): Promise<{ passed: boolean; evidence: string[]; notes?: string }> {
    const control = SOC2_CONTROLS.find(c => c.id === controlId);
    if (!control) {
      throw new Error(`Control ${controlId} not found`);
    }

    try {
      const testResult = await this.executeControlTest(control, testData);
      
      const finding: ComplianceFinding = {
        id: this.generateFindingId(),
        controlId,
        severity: testResult.passed ? 'low' : 'high',
        status: testResult.passed ? 'pass' : 'fail',
        description: `Control test for ${control.title}`,
        evidence: testResult.evidence,
        remediation: testResult.passed ? undefined : 'Review and remediate control implementation'
      };

      this.findings.set(finding.id, finding);

      await dataProtectionManager.logDataAccess(
        'system',
        'CONTROL_TESTED',
        'compliance_control',
        controlId,
        finding.severity as any
      );

      return testResult;
    } catch (error) {
      console.error(`[COMPLIANCE] Control test failed for ${controlId}:`, error);
      return { passed: false, evidence: [], notes: error.message };
    }
  }

  public async checkCompliance(): Promise<{ compliant: boolean; score: number; criticalFindings: ComplianceFinding[] }> {
    const allFindings = Array.from(this.findings.values());
    const criticalFindings = allFindings.filter(f => f.severity === 'critical' && f.status === 'fail');
    const totalFindings = allFindings.length;
    const passedFindings = allFindings.filter(f => f.status === 'pass').length;
    
    const score = totalFindings > 0 ? (passedFindings / totalFindings) * 100 : 100;
    const compliant = criticalFindings.length === 0 && score >= 80;

    return { compliant, score, criticalFindings };
  }

  public async sendIncidentNotifications(incident: ComplianceIncident): Promise<void> {
    const escalationRule = COMPLIANCE_CONFIG.monitoring.escalationRules.find(r => r.severity === incident.severity);
    if (!escalationRule) {
      return;
    }

    // Check cooldown
    const cooldownKey = `incident_notification_${incident.severity}`;
    const lastNotification = this.alertCooldowns.get(cooldownKey) || 0;
    const now = Date.now();
    
    if (now - lastNotification < escalationRule.timeToEscalate * 60 * 1000) {
      return;
    }

    try {
      for (const method of escalationRule.methods) {
        await this.sendNotification(method, escalationRule.recipients, {
          subject: `Compliance Incident: ${incident.title}`,
          message: `Severity: ${incident.severity}\nDescription: ${incident.description}\nSystems Affected: ${incident.affectedSystems.join(', ')}`,
          incident
        });
      }

      this.alertCooldowns.set(cooldownKey, now);
      incident.notificationsSent = true;
      this.incidents.set(incident.id, incident);
    } catch (error) {
      console.error('[COMPLIANCE] Failed to send incident notifications:', error);
    }
  }

  public getSOC2Controls(): SOC2Control[] {
    return [...SOC2_CONTROLS];
  }

  public getComplianceMetrics(): any {
    const allFindings = Array.from(this.findings.values());
    const openIncidents = Array.from(this.incidents.values()).filter(i => i.status === 'open');
    const recentReports = Array.from(this.reports.values()).filter(r => 
      r.generatedAt > new Date(Date.now() - 30 * 24 * 60 * 60 * 1000)
    );

    return {
      totalFindings: allFindings.length,
      criticalFindings: allFindings.filter(f => f.severity === 'critical').length,
      openIncidents: openIncidents.length,
      recentReports: recentReports.length,
      lastReportDate: recentReports.length > 0 ? Math.max(...recentReports.map(r => r.generatedAt.getTime())) : null
    };
  }

  private initializeControls(): void {
    COMPLIANCE_CONFIG.soc2.controls = SOC2_CONTROLS;
  }

  private startMonitoring(): void {
    if (!COMPLIANCE_CONFIG.monitoring.realTime) {
      return;
    }

    this.monitoringInterval = setInterval(() => {
      this.performRealTimeChecks();
    }, 60 * 1000); // Check every minute
  }

  private async performRealTimeChecks(): Promise<void> {
    for (const threshold of COMPLIANCE_CONFIG.monitoring.alertThresholds) {
      try {
        const metricValue = await this.getMetricValue(threshold.metric);
        if (this.evaluateThreshold(metricValue, threshold)) {
          await this.triggerAlert(threshold, metricValue);
        }
      } catch (error) {
        console.error(`[COMPLIANCE] Failed to check metric ${threshold.metric}:`, error);
      }
    }
  }

  private async getMetricValue(metric: string): Promise<number> {
    // Implement metric collection based on your monitoring system
    switch (metric) {
      case 'failed_logins':
        return this.getFailedLoginCount();
      case 'data_access_anomaly':
        return this.getDataAccessAnomalies();
      case 'encryption_failures':
        return this.getEncryptionFailures();
      case 'unauthorized_access_attempts':
        return this.getUnauthorizedAccessAttempts();
      default:
        return 0;
    }
  }

  private evaluateThreshold(value: number, threshold: AlertThreshold): boolean {
    switch (threshold.operator) {
      case '>': return value > threshold.value;
      case '<': return value < threshold.value;
      case '=': return value === threshold.value;
      case '>=': return value >= threshold.value;
      case '<=': return value <= threshold.value;
      default: return false;
    }
  }

  private async triggerAlert(threshold: AlertThreshold, value: number): Promise<void> {
    const cooldownKey = `alert_${threshold.metric}`;
    const lastAlert = this.alertCooldowns.get(cooldownKey) || 0;
    const now = Date.now();

    if (now - lastAlert < threshold.cooldown * 60 * 1000) {
      return;
    }

    await this.createIncident({
      type: 'security',
      severity: threshold.severity,
      status: 'open',
      title: `Alert: ${threshold.metric} threshold exceeded`,
      description: `Metric ${threshold.metric} value ${value} exceeded threshold ${threshold.value}`,
      assignedTo: 'security@fynsor.com',
      affectedSystems: ['monitoring'],
      evidence: [`metric_value: ${value}`, `threshold: ${threshold.value}`]
    });

    this.alertCooldowns.set(cooldownKey, now);
  }

  private getControlsForReportType(type: ComplianceReport['type']): SOC2Control[] {
    switch (type) {
      case 'soc2':
        return SOC2_CONTROLS;
      default:
        return SOC2_CONTROLS; // Default to SOC2 controls
    }
  }

  private generateFindings(controls: SOC2Control[], period: { start: Date; end: Date }): ComplianceFinding[] {
    return controls.map(control => ({
      id: this.generateFindingId(),
      controlId: control.id,
      severity: 'low',
      status: Math.random() > 0.1 ? 'pass' : 'fail', // Simulate test results
      description: `Control testing for ${control.title}`,
      evidence: control.evidence
    }));
  }

  private generateRecommendations(findings: ComplianceFinding[]): string[] {
    const failedFindings = findings.filter(f => f.status === 'fail');
    return failedFindings.map(f => `Address finding ${f.id}: ${f.description}`);
  }

  private calculateRiskScore(likelihood: RiskAssessment['likelihood'], impact: RiskAssessment['impact']): number {
    const likelihoodScore = { very_low: 1, low: 2, medium: 3, high: 4, very_high: 5 }[likelihood];
    const impactScore = { very_low: 1, low: 2, medium: 3, high: 4, very_high: 5 }[impact];
    return likelihoodScore * impactScore;
  }

  private calculateResidualRisk(riskScore: number, mitigations: string[]): number {
    const mitigationFactor = Math.min(mitigations.length * 0.2, 0.8);
    return riskScore * (1 - mitigationFactor);
  }

  private getRiskSeverity(riskScore: number): 'low' | 'medium' | 'high' {
    if (riskScore <= 6) return 'low';
    if (riskScore <= 15) return 'medium';
    return 'high';
  }

  private async executeControlTest(control: SOC2Control, testData: any): Promise<{ passed: boolean; evidence: string[]; notes?: string }> {
    // Implement actual control testing logic based on control type
    // This is a placeholder implementation
    return {
      passed: Math.random() > 0.1, // Simulate 90% pass rate
      evidence: [`test_execution_${Date.now()}.log`, `test_results_${control.id}.json`],
      notes: `Automated test execution for control ${control.id}`
    };
  }

  private async sendNotification(method: string, recipients: string[], content: any): Promise<void> {
    // Implement notification sending based on method
    console.log(`[COMPLIANCE] Sending ${method} notification to ${recipients.join(', ')}:`, content.subject);
  }

  private getFailedLoginCount(): number {
    // Implement based on your authentication logs
    return Math.floor(Math.random() * 10);
  }

  private getDataAccessAnomalies(): number {
    // Implement based on your data access patterns
    return Math.floor(Math.random() * 5);
  }

  private getEncryptionFailures(): number {
    // Implement based on your encryption service logs
    return Math.floor(Math.random() * 2);
  }

  private getUnauthorizedAccessAttempts(): number {
    // Implement based on your access control logs
    return Math.floor(Math.random() * 8);
  }

  private generateIncidentId(): string {
    return `inc_${Date.now()}_${encryptionManager.generateSecureToken(8)}`;
  }

  private generateReportId(): string {
    return `rpt_${Date.now()}_${encryptionManager.generateSecureToken(8)}`;
  }

  private generateFindingId(): string {
    return `fnd_${Date.now()}_${encryptionManager.generateSecureToken(8)}`;
  }

  private generateRiskAssessmentId(): string {
    return `risk_${Date.now()}_${encryptionManager.generateSecureToken(8)}`;
  }

  public destroy(): void {
    if (this.monitoringInterval) {
      clearInterval(this.monitoringInterval);
    }
  }
}

export const complianceManager = ComplianceManager.getInstance();