"use client"

import React, { useState } from 'react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Button } from "@/components/ui/button"
import { BarChart, Bar, LineChart, Line, AreaChart, Area, PieChart, Pie, RadarChart, Radar, ResponsiveContainer, XAxis, YAxis, CartesianGrid, Tooltip, Legend, Cell, Scatter, ScatterChart, Treemap, Sankey, Rectangle } from 'recharts'
import { AlertTriangle, ShieldAlert, UserX, Lock, Activity, Users, Key, AlertCircle, TrendingUp, FileText, Shield, Zap, Target, Eye, Database } from "lucide-react"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Progress } from "@/components/ui/progress"

const COLORS = ['#FF6B6B', '#4ECDC4', '#45B7D1', '#FFA07A', '#98D8C8', '#F7DC6F', '#D1A683']
const RISK_COLORS = {
  Critical: '#FF4136',
  High: '#FF851B',
  Medium: '#FFDC00',
  Low: '#2ECC40'
}

const overviewData = [
  { category: 'Access Attempts', successful: 15000, failed: 3000 },
  { category: 'User Activity', active: 12000, inactive: 3000 },
  { category: 'Security Incidents', resolved: 95, ongoing: 15 },
  { category: 'Policy Violations', minor: 150, major: 30 },
]

const attackPatternData = [
  { name: 'Reconnaissance', frequency: 250, severity: 60, trend: 5 },
  { name: 'Resource Development', frequency: 180, severity: 55, trend: 3 },
  { name: 'Initial Access', frequency: 320, severity: 90, trend: 8 },
  { name: 'Execution', frequency: 280, severity: 85, trend: 6 },
  { name: 'Persistence', frequency: 150, severity: 75, trend: 4 },
  { name: 'Privilege Escalation', frequency: 200, severity: 95, trend: 10 },
  { name: 'Defense Evasion', frequency: 230, severity: 80, trend: 7 },
  { name: 'Credential Access', frequency: 190, severity: 88, trend: 9 },
  { name: 'Discovery', frequency: 270, severity: 70, trend: 5 },
  { name: 'Lateral Movement', frequency: 160, severity: 82, trend: 6 },
  { name: 'Collection', frequency: 140, severity: 78, trend: 4 },
  { name: 'Exfiltration', frequency: 110, severity: 92, trend: 8 },
]

const attackLifecycleData = [
  { name: 'Reconnaissance', value: 250, fill: '#8884d8' },
  { name: 'Weaponization', value: 200, fill: '#83a6ed' },
  { name: 'Delivery', value: 320, fill: '#8dd1e1' },
  { name: 'Exploitation', value: 280, fill: '#82ca9d' },
  { name: 'Installation', value: 230, fill: '#a4de6c' },
  { name: 'Command & Control', value: 190, fill: '#d0ed57' },
  { name: 'Actions on Objectives', value: 270, fill: '#ffc658' },
]

const threatIntelData = [
  { name: 'Malware', value: 35, fill: '#FF6B6B' },
  { name: 'Phishing', value: 28, fill: '#4ECDC4' },
  { name: 'Ransomware', value: 22, fill: '#45B7D1' },
  { name: 'DDoS', value: 15, fill: '#FFA07A' },
  { name: 'Zero-day Exploits', value: 10, fill: '#98D8C8' },
  { name: 'Insider Threats', value: 18, fill: '#F7DC6F' },
  { name: 'Supply Chain Attacks', value: 12, fill: '#D1A683' },
]

const riskTrendData = [
  { month: 'Jan', overallRisk: 65, accessRisk: 70, dataRisk: 60, complianceRisk: 62 },
  { month: 'Feb', overallRisk: 68, accessRisk: 65, dataRisk: 72, complianceRisk: 67 },
  { month: 'Mar', overallRisk: 60, accessRisk: 58, dataRisk: 62, complianceRisk: 65 },
  { month: 'Apr', overallRisk: 72, accessRisk: 75, dataRisk: 68, complianceRisk: 70 },
  { month: 'May', overallRisk: 58, accessRisk: 60, dataRisk: 55, complianceRisk: 59 },
  { month: 'Jun', overallRisk: 63, accessRisk: 62, dataRisk: 64, complianceRisk: 63 },
]

const userBehaviorData = [
  { time: '00:00', normalActivity: 1000, suspiciousActivity: 200, dataAccess: 150 },
  { time: '04:00', normalActivity: 500, suspiciousActivity: 300, dataAccess: 100 },
  { time: '08:00', normalActivity: 2000, suspiciousActivity: 400, dataAccess: 300 },
  { time: '12:00', normalActivity: 3000, suspiciousActivity: 350, dataAccess: 450 },
  { time: '16:00', normalActivity: 2500, suspiciousActivity: 450, dataAccess: 400 },
  { time: '20:00', normalActivity: 1500, suspiciousActivity: 250, dataAccess: 200 },
]

const userRiskDistributionData = [
  {
    name: 'IT',
    children: [
      { name: 'High Risk', size: 15, color: '#FF4136' },
      { name: 'Medium Risk', size: 25, color: '#FF851B' },
      { name: 'Low Risk', size: 60, color: '#2ECC40' },
    ],
  },
  {
    name: 'Finance',
    children: [
      { name: 'High Risk', size: 20, color: '#FF4136' },
      { name: 'Medium Risk', size: 30, color: '#FF851B' },
      { name: 'Low Risk', size: 50, color: '#2ECC40' },
    ],
  },
  {
    name: 'HR',
    children: [
      { name: 'High Risk', size: 10, color: '#FF4136' },
      { name: 'Medium Risk', size: 20, color: '#FF851B' },
      { name: 'Low Risk', size: 70, color: '#2ECC40' },
    ],
  },
  {
    name: 'Sales',
    children: [
      { name: 'High Risk', size: 25, color: '#FF4136' },
      { name: 'Medium Risk', size: 35, color: '#FF851B' },
      { name: 'Low Risk', size: 40, color: '#2ECC40' },
    ],
  },
  {
    name: 'Engineering',
    children: [
      { name: 'High Risk', size: 18, color: '#FF4136' },
      { name: 'Medium Risk', size: 32, color: '#FF851B' },
      { name: 'Low Risk', size: 50, color: '#2ECC40' },
    ],
  },
]

const highRiskUsersData = [
  { id: 1, username: 'john.doe', riskScore: 85, lastActivity: '2023-06-15', riskFactors: 'Multiple failed logins, Unusual access patterns', department: 'IT' },
  { id: 2, username: 'jane.smith', riskScore: 78, lastActivity: '2023-06-14', riskFactors: 'Accessing sensitive data, Login from new location', department: 'Finance' },
  { id: 3, username: 'admin.user', riskScore: 92, lastActivity: '2023-06-16', riskFactors: 'Elevated privileges, Unusual time access', department: 'IT' },
  { id: 4, username: 'guest.access', riskScore: 70, lastActivity: '2023-06-13', riskFactors: 'Dormant account activity, Multiple device logins', department: 'HR' },
  { id: 5, username: 'dev.team', riskScore: 88, lastActivity: '2023-06-16', riskFactors: 'Frequent privileged operations, Large data transfers', department: 'Engineering' },
]

const complianceStatusData = [
  { regulation: 'GDPR', complianceScore: 92, lastAudit: '2023-05-15', keyFindings: 'Minor improvements in data retention policies needed', trend: 2 },
  { regulation: 'HIPAA', complianceScore: 88, lastAudit: '2023-04-22', keyFindings: 'Update required for access control in certain systems', trend: -1 },
  { regulation: 'PCI DSS', complianceScore: 95, lastAudit: '2023-06-01', keyFindings: 'Encryption standards meet requirements, minor documentation updates needed', trend: 0 },
  { regulation: 'SOX', complianceScore: 90, lastAudit: '2023-03-10', keyFindings: 'Financial systems access controls are robust, some process documentation needs revision', trend: 1 },
]

const complianceImprovementData = [
  { regulation: 'GDPR', currentScore: 92, targetScore: 98, gap: 6 },
  { regulation: 'HIPAA', currentScore: 88, targetScore: 95, gap: 7 },
  { regulation: 'PCI DSS', currentScore: 95, targetScore: 100, gap: 5 },
  { regulation: 'SOX', currentScore: 90, targetScore: 97, gap: 7 },
  { regulation: 'ISO 27001', currentScore: 85, targetScore: 95, gap: 10 },
]

const actionItemsData = [
  { category: 'Access Control', completed: 15, inProgress: 8, notStarted: 5 },
  { category: 'Data Protection', completed: 12, inProgress: 10, notStarted: 6 },
  { category: 'Threat Mitigation', completed: 18, inProgress: 7, notStarted: 3 },
  { category: 'Compliance', completed: 20, inProgress: 5, notStarted: 2 },
  { category: 'User Training', completed: 8, inProgress: 12, notStarted: 8 },
]

const vulnerabilityData = [
  { name: 'Critical', value: 5 },
  { name: 'High', value: 15 },
  { name: 'Medium', value: 30 },
  { name: 'Low', value: 50 },
]

const incidentResponseData = [
  { name: 'Detection', time: 10 },
  { name: 'Analysis', time: 25 },
  { name: 'Containment', time: 15 },
  { name: 'Eradication', time: 30 },
  { name: 'Recovery', time: 20 },
]

export function AiraThreatIntelDashboard() {
  const [selectedAttackPattern, setSelectedAttackPattern] = useState(null)

  const handleAttackPatternClick = (entry) => {
    setSelectedAttackPattern(entry.name)
  }

  const renderRecommendations = () => {
    if (!selectedAttackPattern) return null

    const recommendations = {
      'Reconnaissance': [
        "Implement robust network segmentation to limit visibility",
        "Use deception technologies to mislead attackers",
        "Regularly conduct external vulnerability scans",
        "Monitor for unusual port scans or probing activities"
      ],
      'Resource Development': [
        "Implement strong email filtering to prevent phishing attempts",
        "Use threat intelligence feeds to identify malicious infrastructure",
        "Monitor for suspicious domain registrations similar to your organization",
        "Implement DNS-based security measures"
      ],
      'Initial Access': [
        "Enforce multi-factor authentication across all systems",
        "Conduct regular phishing awareness training for employees",
        "Implement strict access controls and least privilege principles",
        "Use endpoint detection and response (EDR) solutions"
      ],
      'Execution': [
        "Implement application whitelisting to prevent unauthorized code execution",
        "Use behavior-based malware detection systems",
        "Regularly update and patch all systems and applications",
        "Implement sandboxing technologies for email attachments and downloads"
      ],
      'Persistence': [
        "Regularly audit user accounts and access privileges",
        "Implement robust change management processes",
        "Use endpoint detection and response (EDR) solutions",
        "Monitor for unusual scheduled tasks or startup programs"
      ],
      'Privilege Escalation': [
        "Implement strict role-based access control (RBAC)",
        "Regularly audit and review user privileges",
        "Use Privileged Access Management (PAM) solutions",
        "Monitor for unusual privilege changes or escalations"
      ],
      'Defense Evasion': [
        "Implement advanced endpoint protection with behavioral analysis",
        "Use deception technologies to detect evasion attempts",
        "Regularly update intrusion detection/prevention systems",
        "Implement robust logging and log analysis"
      ],
      'Credential Access': [
        "Enforce strong password policies and regular password changes",
        "Implement multi-factor authentication",
        "Use password managers to encourage complex, unique passwords",
        "Monitor for unusual authentication patterns or credential dumping activities"
      ],
      'Discovery': [
        "Implement network segmentation to limit lateral movement",
        "Use honeypots to detect internal reconnaissance",
        "Monitor for unusual network scanning or enumeration activities",
        "Implement robust logging and alerting for sensitive systems"
      ],
      'Lateral Movement': [
        "Implement network segmentation and micro-segmentation",
        "Use jump servers and privileged access workstations",
        "Monitor for unusual remote access or lateral movement patterns",
        "Implement strong authentication for all internal systems"
      ],
      'Collection': [
        "Implement data loss prevention (DLP) solutions",
        "Use encryption for sensitive data at rest and in transit",
        "Monitor for unusual data access or transfer patterns",
        "Implement strict access controls based on the principle of least privilege"
      ],
      'Exfiltration': [
        "Implement robust data loss prevention (DLP) solutions",
        "Monitor for unusual outbound network traffic",
        "Use egress filtering and monitor for unusual protocols",
        "Implement encryption for sensitive data and monitor for decryption attempts"
      ],
    }

    return (
      <Card className="mt-4">
        <CardHeader>
          <CardTitle>Mitigation Recommendations for {selectedAttackPattern}</CardTitle>
        </CardHeader>
        <CardContent>
          <ul className="list-disc pl-5">
            {recommendations[selectedAttackPattern].map((rec, index) => (
              <li key={index} className="mb-2">{rec}</li>
            ))}
          </ul>
        </CardContent>
      </Card>
    )
  }

  return (
    <div className="p-4 bg-gradient-to-br from-gray-100 to-blue-50 min-h-screen">
      <h1 className="text-4xl font-bold mb-6 text-center text-blue-800">AIRA Threat Intel Dashboard</h1>
      <Tabs defaultValue="overview" className="space-y-4">
        <TabsList className="grid w-full grid-cols-1 md:grid-cols-5 bg-blue-100 rounded-lg p-1 shadow">
          <TabsTrigger value="overview" className="data-[state=active]:bg-white">Overview</TabsTrigger>
          <TabsTrigger value="threats" className="data-[state=active]:bg-white">Threat Landscape</TabsTrigger>
          <TabsTrigger value="users" className="data-[state=active]:bg-white">User Insights</TabsTrigger>
          <TabsTrigger value="compliance" className="data-[state=active]:bg-white">Compliance</TabsTrigger>
          <TabsTrigger value="actionItems" className="data-[state=active]:bg-white">Action Items</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            <Card className="bg-white shadow-lg">
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Overall Risk Score</CardTitle>
                <Shield className="h-4 w-4 text-red-600" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">72/100</div>
                <p className="text-xs text-red-600">High Risk - Immediate Action Required</p>
                <Progress value={72} className="mt-2" />
              </CardContent>
            </Card>
            <Card className="bg-white shadow-lg">
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Active Threats</CardTitle>
                <AlertTriangle className="h-4 w-4 text-yellow-600" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">17</div>
                <p className="text-xs text-yellow-600">5 Critical, 12 High</p>
                <div className="mt-2 flex items-center space-x-2">
                  <span className="text-xs font-medium">Trend:</span>
                  <TrendingUp className="h-4 w-4 text-red-500" />
                  <span className="text-xs text-red-500">+15% this week</span>
                </div>
              </CardContent>
            </Card>
            <Card className="bg-white shadow-lg">
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">User Risk Index</CardTitle>
                <Users className="h-4 w-4 text-blue-600" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">63%</div>
                <p className="text-xs text-blue-600">+5% from last month</p>
                <Progress value={63} className="mt-2" />
              </CardContent>
            </Card>
            <Card className="bg-white shadow-lg">
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Compliance Score</CardTitle>
                <FileText className="h-4 w-4 text-green-600" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">91%</div>
                <p className="text-xs text-green-600">-2% from last quarter</p>
                <Progress value={91} className="mt-2" />
              </CardContent>
            </Card>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Card className="bg-white shadow-lg">
              <CardHeader>
                <CardTitle>Risk Trend Analysis</CardTitle>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={300}>
                  <LineChart data={riskTrendData}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="month" />
                    <YAxis />
                    <Tooltip />
                    <Legend />
                    <Line type="monotone" dataKey="overallRisk" stroke="#8884d8" name="Overall Risk" />
                    <Line type="monotone" dataKey="accessRisk" stroke="#82ca9d" name="Access Risk" />
                    <Line type="monotone" dataKey="dataRisk" stroke="#ffc658" name="Data Risk" />
                    <Line type="monotone" dataKey="complianceRisk" stroke="#ff7300" name="Compliance Risk" />
                  </LineChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
            <Card className="bg-white shadow-lg">
              <CardHeader>
                <CardTitle>Security Overview</CardTitle>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={300}>
                  <BarChart data={overviewData}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="category" />
                    <YAxis />
                    <Tooltip />
                    <Legend />
                    <Bar dataKey="successful" stackId="a" fill="#82ca9d" name="Successful/Active/Resolved" />
                    <Bar dataKey="failed" stackId="a" fill="#8884d8" name="Failed/Inactive/Ongoing" />
                    <Bar dataKey="minor" stackId="a" fill="#ffc658" name="Minor Violations" />
                    <Bar dataKey="major" stackId="a" fill="#ff7300" name="Major Violations" />
                  </BarChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </div>
          <Card className="bg-white shadow-lg">
            <CardHeader>
              <CardTitle>Critical Insights</CardTitle>
            </CardHeader>
            <CardContent>
              <ul className="space-y-2">
                <li className="flex items-center space-x-2">
                  <AlertCircle className="h-5 w-5 text-red-500" />
                  <span>Significant increase in phishing attempts targeting finance department</span>
                </li>
                <li className="flex items-center space-x-2">
                  <Zap className="h-5 w-5 text-yellow-500" />
                  <span>Unusual spike in failed login attempts from international IP addresses</span>
                </li>
                <li className="flex items-center space-x-2">
                  <Target className="h-5 w-5 text-blue-500" />
                  <span>Three high-privilege accounts showing signs of potential compromise</span>
                </li>
                <li className="flex items-center space-x-2">
                  <Eye className="h-5 w-5 text-green-500" />
                  <span>Improved detection of lateral movement attempts in the network</span>
                </li>
              </ul>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="threats" className="space-y-4">
          <Card className="bg-white shadow-lg">
            <CardHeader>
              <CardTitle>Attack Pattern Analysis</CardTitle>
              <CardDescription>Click on a point for mitigation recommendations</CardDescription>
            </CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={400}>
                <ScatterChart margin={{ top: 20, right: 20, bottom: 20, left: 20 }}>
                  <CartesianGrid />
                  <XAxis type="number" dataKey="frequency" name="Frequency" unit=" incidents" />
                  <YAxis type="number" dataKey="severity" name="Severity" unit="/100" />
                  <Tooltip cursor={{ strokeDasharray: '3 3' }} />
                  <Scatter name="Attack Patterns" data={attackPatternData} fill="#8884d8">
                    {attackPatternData.map((entry, index) => (
                      <Cell
                        key={`cell-${index}`}
                        fill={COLORS[index % COLORS.length]}
                        onClick={() => handleAttackPatternClick(entry)}
                      />
                    ))}
                  </Scatter>
                </ScatterChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
          {renderRecommendations()}
          <Card className="bg-white shadow-lg">
            <CardHeader>
              <CardTitle>Attack Lifecycle Analysis</CardTitle>
            </CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={400}>
                <AreaChart data={attackLifecycleData}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="name" />
                  <YAxis />
                  <Tooltip />
                  <Area type="monotone" dataKey="value" stroke="#8884d8" fill="#8884d8" />
                </AreaChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Card className="bg-white shadow-lg">
              <CardHeader>
                <CardTitle>Threat Intelligence Distribution</CardTitle>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={300}>
                  <PieChart>
                    <Pie
                      data={threatIntelData}
                      cx="50%"
                      cy="50%"
                      labelLine={false}
                      outerRadius={80}
                      fill="#8884d8"
                      dataKey="value"
                      label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                    >
                      {threatIntelData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.fill} />
                      ))}
                    </Pie>
                    <Tooltip />
                    <Legend />
                  </PieChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
            <Card className="bg-white shadow-lg">
              <CardHeader>
                <CardTitle>Vulnerability Distribution</CardTitle>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={300}>
                  <PieChart>
                    <Pie
                      data={vulnerabilityData}
                      cx="50%"
                      cy="50%"
                      labelLine={false}
                      outerRadius={80}
                      fill="#8884d8"
                      dataKey="value"
                      label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                    >
                      {vulnerabilityData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                      ))}
                    </Pie>
                    <Tooltip />
                    <Legend />
                  </PieChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </div>
          <Card className="bg-white shadow-lg">
            <CardHeader>
              <CardTitle>Incident Response Time</CardTitle>
            </CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={incidentResponseData}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="name" />
                  <YAxis />
                  <Tooltip />
                  <Legend />
                  <Bar dataKey="time" fill="#8884d8" name="Time (minutes)" />
                </BarChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="users" className="space-y-4">
          <Card className="bg-white shadow-lg">
            <CardHeader>
              <CardTitle>User Behavior Analysis</CardTitle>
            </CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={300}>
                <AreaChart data={userBehaviorData}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="time" />
                  <YAxis />
                  <Tooltip />
                  <Legend />
                  <Area type="monotone" dataKey="normalActivity" stackId="1" stroke="#8884d8" fill="#8884d8" name="Normal Activity" />
                  <Area type="monotone" dataKey="suspiciousActivity" stackId="1" stroke="#82ca9d" fill="#82ca9d" name="Suspicious Activity" />
                  <Area type="monotone" dataKey="dataAccess" stackId="1" stroke="#ffc658" fill="#ffc658" name="Data Access" />
                </AreaChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
          <Card className="bg-white shadow-lg">
            <CardHeader>
              <CardTitle>High-Risk Users</CardTitle>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Username</TableHead>
                    <TableHead>Risk Score</TableHead>
                    <TableHead>Department</TableHead>
                    <TableHead>Last Activity</TableHead>
                    <TableHead>Risk Factors</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {highRiskUsersData.map((user) => (
                    <TableRow key={user.id}>
                      <TableCell>{user.username}</TableCell>
                      <TableCell>
                        <span className={`font-bold ${user.riskScore > 80 ? 'text-red-500' : 'text-yellow-500'}`}>
                          {user.riskScore}
                        </span>
                      </TableCell>
                      <TableCell>{user.department}</TableCell>
                      <TableCell>{user.lastActivity}</TableCell>
                      <TableCell>{user.riskFactors}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
          <Card className="bg-white shadow-lg">
            <CardHeader>
              <CardTitle>User Risk Distribution by Department</CardTitle>
            </CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={300}>
                <Treemap
                  data={userRiskDistributionData}
                  dataKey="size"
                  aspectRatio={4 / 3}
                  stroke="#fff"
                  content={<CustomizedContent colors={userRiskDistributionData} />}
                >
                  <Tooltip content={<CustomTooltip />} />
                </Treemap>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="compliance" className="space-y-4">
          <Card className="bg-white shadow-lg">
            <CardHeader>
              <CardTitle>Compliance Status Overview</CardTitle>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Regulation</TableHead>
                    <TableHead>Compliance Score</TableHead>
                    <TableHead>Trend</TableHead>
                    <TableHead>Last Audit</TableHead>
                    <TableHead>Key Findings</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {complianceStatusData.map((item, index) => (
                    <TableRow key={index}>
                      <TableCell>{item.regulation}</TableCell>
                      <TableCell>
                        <span className={`font-bold ${
                          item.complianceScore > 90 ? 'text-green-500' :
                          item.complianceScore > 80 ? 'text-yellow-500' : 'text-red-500'
                        }`}>
                          {item.complianceScore}%
                        </span>
                      </TableCell>
                      <TableCell>
                        {item.trend > 0 ? (
                          <TrendingUp className="h-4 w-4 text-green-500" />
                        ) : item.trend < 0 ? (
                          <TrendingUp className="h-4 w-4 text-red-500 transform rotate-180" />
                        ) : (
                          <span>-</span>
                        )}
                      </TableCell>
                      <TableCell>{item.lastAudit}</TableCell>
                      <TableCell>{item.keyFindings}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
          <Card className="bg-white shadow-lg">
            <CardHeader>
              <CardTitle>Compliance Improvement Roadmap</CardTitle>
            </CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={complianceImprovementData}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="regulation" />
                  <YAxis />
                  <Tooltip />
                  <Legend />
                  <Bar dataKey="currentScore" fill="#8884d8" name="Current Score" />
                  <Bar dataKey="gap" fill="#82ca9d" name="Improvement Gap" />
                </BarChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="actionItems" className="space-y-4">
          <Card className="bg-white shadow-lg">
            <CardHeader>
              <CardTitle>Action Items Progress</CardTitle>
            </CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={actionItemsData}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="category" />
                  <YAxis />
                  <Tooltip />
                  <Legend />
                  <Bar dataKey="completed" stackId="a" fill="#82ca9d" name="Completed" />
                  <Bar dataKey="inProgress" stackId="a" fill="#ffc658" name="In Progress" />
                  <Bar dataKey="notStarted" stackId="a" fill="#ff7300" name="Not Started" />
                </BarChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
          <Card className="bg-white shadow-lg">
            <CardHeader>
              <CardTitle>Executive Action Items</CardTitle>
            </CardHeader>
            <CardContent>
              <ul className="space-y-2">
                <li className="flex items-center space-x-2">
                  <Button size="sm" variant="destructive">Critical</Button>
                  <span>Review and update access control policies for high-risk users</span>
                </li>
                <li className="flex items-center space-x-2">
                  <Button size="sm" variant="destructive">Critical</Button>
                  <span>Initiate company-wide phishing awareness campaign</span>
                </li>
                <li className="flex items-center space-x-2">
                  <Button size="sm" variant="destructive">Critical</Button>
                  <span>Implement multi-factor authentication for all privileged accounts</span>
                </li>
                <li className="flex items-center space-x-2">
                  <Button size="sm" variant="warning">High</Button>
                  <span>Allocate budget for advanced threat detection tools</span>
                </li>
                <li className="flex items-center space-x-2">
                  <Button size="sm" variant="warning">High</Button>
                  <span>Schedule quarterly compliance review meetings</span>
                </li>
                <li className="flex items-center space-x-2">
                  <Button size="sm" variant="secondary">Medium</Button>
                  <span>Develop a formal Incident Response Plan</span>
                </li>
                <li className="flex items-center space-x-2">
                  <Button size="sm" variant="secondary">Medium</Button>
                  <span>Conduct a third-party security audit</span>
                </li>
              </ul>
            </CardContent>
          </Card>
          <Card className="bg-white shadow-lg">
            <CardHeader>
              <CardTitle>Risk Mitigation Strategy</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="mb-4">Based on the current threat landscape and user risk profiles, we recommend the following strategic initiatives:</p>
              <ol className="list-decimal pl-5 space-y-2">
                <li>Implement a Zero Trust Architecture to enhance overall security posture</li>
                <li>Invest in AI-driven User and Entity Behavior Analytics (UEBA) for proactive threat detection</li>
                <li>Establish a formal Security Operations Center (SOC) for 24/7 monitoring and rapid incident response</li>
                <li>Conduct regular third-party security audits and penetration testing</li>
                <li>Develop a comprehensive data classification and protection strategy</li>
                <li>Implement a Privileged Access Management (PAM) solution to control and monitor high-risk accounts</li>
                <li>Enhance network segmentation to limit the potential impact of breaches</li>
                <li>Develop and implement a formal patch management process across all systems</li>
              </ol>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}

const CustomizedContent = (props) => {
  const { root, depth, x, y, width, height, index, colors, name } = props;

  return (
    <g>
      <Rectangle
        x={x}
        y={y}
        width={width}
        height={height}
        style={{
          fill: depth < 2 ? colors[Math.floor(index / 3)].children[index % 3].color : "#ffffff00",
          stroke: "#fff",
          strokeWidth: 2 / (depth + 1e-10),
          strokeOpacity: 1 / (depth + 1e-10),
        }}
      />
      {depth === 1 ? (
        <text
          x={x + width / 2}
          y={y + height / 2 + 7}
          textAnchor="middle"
          fill="#fff"
          fontSize={14}
        >
          {name}
        </text>
      ) : null}
      {depth === 1 ? (
        <text
          x={x + 4}
          y={y + 18}
          fill="#fff"
          fontSize={16}
          fillOpacity={0.9}
        >
          {index + 1}
        </text>
      ) : null}
    </g>
  );
};

const CustomTooltip = ({ active, payload }) => {
  if (active && payload && payload.length) {
    const data = payload[0].payload;
    return (
      <div className="bg-white p-2 border border-gray-300 rounded shadow-md">
        <p>{`${data.name} : ${data.size}`}</p>
      </div>
    );
  }
  return null;
};