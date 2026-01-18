import { useState, useEffect, useCallback } from "react";
import { useParams, useNavigate } from "react-router-dom";
import axios from "axios";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { 
  Mail, 
  CheckCircle2, 
  XCircle, 
  AlertTriangle,
  HelpCircle,
  Download,
  ArrowLeft,
  RefreshCw,
  ChevronDown,
  Filter
} from "lucide-react";

const API = `${process.env.REACT_APP_BACKEND_URL}/api`;

const statusConfig = {
  valid: { 
    icon: CheckCircle2, 
    color: "text-emerald-600", 
    bg: "bg-emerald-50", 
    border: "border-emerald-200",
    label: "Valid"
  },
  invalid: { 
    icon: XCircle, 
    color: "text-rose-600", 
    bg: "bg-rose-50", 
    border: "border-rose-200",
    label: "Invalid"
  },
  risky: { 
    icon: AlertTriangle, 
    color: "text-amber-600", 
    bg: "bg-amber-50", 
    border: "border-amber-200",
    label: "Risky"
  },
  unknown: { 
    icon: HelpCircle, 
    color: "text-slate-500", 
    bg: "bg-slate-50", 
    border: "border-slate-200",
    label: "Unknown"
  }
};

export default function ResultsPage() {
  const { jobId } = useParams();
  const navigate = useNavigate();
  const [job, setJob] = useState(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState("all");

  const fetchJob = useCallback(async () => {
    try {
      const response = await axios.get(`${API}/validate/job/${jobId}`);
      setJob(response.data);
      setLoading(false);
    } catch (error) {
      toast.error("Failed to load job results");
      setLoading(false);
    }
  }, [jobId]);

  useEffect(() => {
    fetchJob();
    
    // Poll for updates if job is processing
    const interval = setInterval(() => {
      if (job?.status === 'pending' || job?.status === 'processing') {
        fetchJob();
      }
    }, 2000);

    return () => clearInterval(interval);
  }, [fetchJob, job?.status]);

  const handleExport = async (statusFilter = null) => {
    try {
      const url = statusFilter 
        ? `${API}/validate/job/${jobId}/export?status_filter=${statusFilter}`
        : `${API}/validate/job/${jobId}/export`;
      
      const response = await axios.get(url, { responseType: 'blob' });
      const blob = new Blob([response.data], { type: 'text/csv' });
      const downloadUrl = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = downloadUrl;
      link.download = `email_validation_${statusFilter || 'all'}_${jobId}.csv`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(downloadUrl);
      toast.success("Export downloaded successfully");
    } catch (error) {
      toast.error("Failed to export results");
    }
  };

  const filteredResults = job?.results?.filter(r => {
    if (activeTab === "all") return true;
    return r.status === activeTab;
  }) || [];

  const progress = job ? (job.processed_emails / job.total_emails) * 100 : 0;

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-50">
        <div className="text-center">
          <div className="w-12 h-12 border-4 border-indigo-200 border-t-indigo-600 rounded-full animate-spin mx-auto" />
          <p className="mt-4 text-slate-600">Loading results...</p>
        </div>
      </div>
    );
  }

  if (!job) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-50">
        <div className="text-center">
          <XCircle className="w-12 h-12 text-rose-500 mx-auto" />
          <p className="mt-4 text-slate-600">Job not found</p>
          <Button 
            onClick={() => navigate('/')} 
            className="mt-4"
            data-testid="back-home-btn"
          >
            Back to Home
          </Button>
        </div>
      </div>
    );
  }

  const isProcessing = job.status === 'pending' || job.status === 'processing';

  return (
    <div className="min-h-screen bg-slate-50">
      {/* Header */}
      <header className="glass-header sticky top-0 z-50 py-4">
        <div className="max-w-7xl mx-auto px-6 md:px-12 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <Button 
              variant="ghost" 
              size="sm"
              onClick={() => navigate('/')}
              className="text-slate-600 hover:text-slate-900"
              data-testid="back-btn"
            >
              <ArrowLeft className="w-4 h-4 mr-2" />
              Back
            </Button>
            <div className="h-6 w-px bg-slate-200" />
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-indigo-600 flex items-center justify-center">
                <Mail className="w-5 h-5 text-white" />
              </div>
              <span className="text-xl font-bold text-slate-900" style={{ fontFamily: 'Manrope' }}>
                VerifyMail
              </span>
            </div>
          </div>
          <div className="flex items-center gap-3">
            {isProcessing && (
              <Button 
                variant="outline" 
                size="sm"
                onClick={fetchJob}
                className="text-slate-600"
                data-testid="refresh-btn"
              >
                <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                Refreshing...
              </Button>
            )}
            {!isProcessing && job.results?.length > 0 && (
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button 
                    className="bg-indigo-600 hover:bg-indigo-700 text-white"
                    data-testid="export-dropdown-btn"
                  >
                    <Download className="w-4 h-4 mr-2" />
                    Export
                    <ChevronDown className="w-4 h-4 ml-2" />
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end" className="w-48">
                  <DropdownMenuItem 
                    onClick={() => handleExport()}
                    data-testid="export-all-btn"
                  >
                    <Filter className="w-4 h-4 mr-2" />
                    Export All
                  </DropdownMenuItem>
                  <DropdownMenuItem 
                    onClick={() => handleExport('valid')}
                    data-testid="export-valid-btn"
                  >
                    <CheckCircle2 className="w-4 h-4 mr-2 text-emerald-600" />
                    Export Valid Only
                  </DropdownMenuItem>
                  <DropdownMenuItem 
                    onClick={() => handleExport('invalid')}
                    data-testid="export-invalid-btn"
                  >
                    <XCircle className="w-4 h-4 mr-2 text-rose-600" />
                    Export Invalid Only
                  </DropdownMenuItem>
                  <DropdownMenuItem 
                    onClick={() => handleExport('risky')}
                    data-testid="export-risky-btn"
                  >
                    <AlertTriangle className="w-4 h-4 mr-2 text-amber-600" />
                    Export Risky Only
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            )}
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-6 md:px-12 py-8">
        {/* Progress Section */}
        {isProcessing && (
          <Card className="mb-8 border-indigo-100 bg-indigo-50/50">
            <CardContent className="py-6">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-full bg-indigo-100 flex items-center justify-center">
                    <RefreshCw className="w-5 h-5 text-indigo-600 animate-spin" />
                  </div>
                  <div>
                    <h3 className="font-semibold text-slate-900" style={{ fontFamily: 'Manrope' }}>
                      Validating Emails
                    </h3>
                    <p className="text-sm text-slate-600">
                      {job.processed_emails} of {job.total_emails} processed
                    </p>
                  </div>
                </div>
                <span className="text-2xl font-bold text-indigo-600" style={{ fontFamily: 'Manrope' }}>
                  {Math.round(progress)}%
                </span>
              </div>
              <Progress value={progress} className="h-2 bg-indigo-100" data-testid="progress-bar" />
            </CardContent>
          </Card>
        )}

        {/* Stats Cards */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
          <Card className="metric-card bg-white border border-slate-100 shadow-sm">
            <CardContent className="py-5 px-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-slate-500 font-medium">Total</p>
                  <p className="text-2xl font-bold text-slate-900 mt-1" style={{ fontFamily: 'Manrope' }} data-testid="total-count">
                    {job.total_emails}
                  </p>
                </div>
                <div className="w-10 h-10 rounded-xl bg-slate-100 flex items-center justify-center">
                  <Mail className="w-5 h-5 text-slate-600" />
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="metric-card bg-white border border-emerald-100 shadow-sm">
            <CardContent className="py-5 px-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-emerald-600 font-medium">Valid</p>
                  <p className="text-2xl font-bold text-emerald-700 mt-1" style={{ fontFamily: 'Manrope' }} data-testid="valid-count">
                    {job.valid_count}
                  </p>
                </div>
                <div className="w-10 h-10 rounded-xl bg-emerald-50 flex items-center justify-center">
                  <CheckCircle2 className="w-5 h-5 text-emerald-600" />
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="metric-card bg-white border border-rose-100 shadow-sm">
            <CardContent className="py-5 px-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-rose-600 font-medium">Invalid</p>
                  <p className="text-2xl font-bold text-rose-700 mt-1" style={{ fontFamily: 'Manrope' }} data-testid="invalid-count">
                    {job.invalid_count}
                  </p>
                </div>
                <div className="w-10 h-10 rounded-xl bg-rose-50 flex items-center justify-center">
                  <XCircle className="w-5 h-5 text-rose-600" />
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="metric-card bg-white border border-amber-100 shadow-sm">
            <CardContent className="py-5 px-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-amber-600 font-medium">Risky</p>
                  <p className="text-2xl font-bold text-amber-700 mt-1" style={{ fontFamily: 'Manrope' }} data-testid="risky-count">
                    {job.risky_count}
                  </p>
                </div>
                <div className="w-10 h-10 rounded-xl bg-amber-50 flex items-center justify-center">
                  <AlertTriangle className="w-5 h-5 text-amber-600" />
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Results Table */}
        <Card className="bg-white border border-slate-100 shadow-sm rounded-xl overflow-hidden">
          <CardHeader className="border-b border-slate-100 bg-slate-50/50 py-4">
            <div className="flex items-center justify-between">
              <CardTitle className="text-lg font-semibold text-slate-900" style={{ fontFamily: 'Manrope' }}>
                Validation Results
              </CardTitle>
              <Tabs value={activeTab} onValueChange={setActiveTab}>
                <TabsList className="bg-slate-100">
                  <TabsTrigger value="all" className="text-xs" data-testid="tab-all">
                    All ({job.results?.length || 0})
                  </TabsTrigger>
                  <TabsTrigger value="valid" className="text-xs" data-testid="tab-valid">
                    Valid ({job.valid_count})
                  </TabsTrigger>
                  <TabsTrigger value="invalid" className="text-xs" data-testid="tab-invalid">
                    Invalid ({job.invalid_count})
                  </TabsTrigger>
                  <TabsTrigger value="risky" className="text-xs" data-testid="tab-risky">
                    Risky ({job.risky_count})
                  </TabsTrigger>
                </TabsList>
              </Tabs>
            </div>
          </CardHeader>
          <CardContent className="p-0">
            <ScrollArea className="h-[500px]">
              <Table>
                <TableHeader>
                  <TableRow className="bg-slate-50/50 hover:bg-slate-50/50">
                    <TableHead className="font-semibold text-slate-600 uppercase text-xs tracking-wider">
                      Email
                    </TableHead>
                    <TableHead className="font-semibold text-slate-600 uppercase text-xs tracking-wider">
                      Status
                    </TableHead>
                    <TableHead className="font-semibold text-slate-600 uppercase text-xs tracking-wider hidden md:table-cell">
                      Checks
                    </TableHead>
                    <TableHead className="font-semibold text-slate-600 uppercase text-xs tracking-wider">
                      Reason
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredResults.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={4} className="text-center py-12 text-slate-500">
                        {isProcessing ? "Processing emails..." : "No results to display"}
                      </TableCell>
                    </TableRow>
                  ) : (
                    filteredResults.map((result, index) => {
                      const config = statusConfig[result.status];
                      const StatusIcon = config.icon;
                      return (
                        <TableRow key={index} className="email-row border-b border-slate-50">
                          <TableCell className="font-mono text-sm text-slate-800" data-testid={`email-${index}`}>
                            {result.email}
                          </TableCell>
                          <TableCell>
                            <Badge 
                              variant="outline" 
                              className={`${config.bg} ${config.color} ${config.border} font-medium`}
                              data-testid={`status-${index}`}
                            >
                              <StatusIcon className="w-3 h-3 mr-1" />
                              {config.label}
                            </Badge>
                          </TableCell>
                          <TableCell className="hidden md:table-cell">
                            <div className="flex items-center gap-2 flex-wrap">
                              <span className={`text-xs px-2 py-0.5 rounded ${result.format_valid ? 'bg-emerald-50 text-emerald-600' : 'bg-rose-50 text-rose-600'}`}>
                                Format
                              </span>
                              <span className={`text-xs px-2 py-0.5 rounded ${result.mx_valid ? 'bg-emerald-50 text-emerald-600' : 'bg-rose-50 text-rose-600'}`}>
                                MX
                              </span>
                              {result.smtp_valid !== null && result.smtp_valid !== undefined && (
                                <span className={`text-xs px-2 py-0.5 rounded ${result.smtp_valid ? 'bg-emerald-50 text-emerald-600' : 'bg-rose-50 text-rose-600'}`}>
                                  SMTP
                                </span>
                              )}
                              {result.is_disposable && (
                                <span className="text-xs px-2 py-0.5 rounded bg-amber-50 text-amber-600">
                                  Disposable
                                </span>
                              )}
                              {result.is_catchall && (
                                <span className="text-xs px-2 py-0.5 rounded bg-amber-50 text-amber-600">
                                  Catch-all
                                </span>
                              )}
                              {result.quality_score > 0 && (
                                <span className="text-xs px-2 py-0.5 rounded bg-indigo-50 text-indigo-600">
                                  {Math.round(result.quality_score * 100)}%
                                </span>
                              )}
                            </div>
                          </TableCell>
                          <TableCell className="text-sm text-slate-600 max-w-[200px] truncate" data-testid={`reason-${index}`}>
                            {result.reason}
                          </TableCell>
                        </TableRow>
                      );
                    })
                  )}
                </TableBody>
              </Table>
            </ScrollArea>
          </CardContent>
        </Card>
      </main>
    </div>
  );
}
