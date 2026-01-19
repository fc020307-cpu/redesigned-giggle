import { useState, useCallback } from "react";
import { useNavigate, Link } from "react-router-dom";
import axios from "axios";
import { toast } from "sonner";
import { useAuth } from "@/context/AuthContext";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Card, CardContent } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { 
  Upload, 
  Mail, 
  CheckCircle2, 
  XCircle, 
  AlertTriangle,
  FileText,
  Zap,
  Shield,
  Clock,
  User
} from "lucide-react";

const API = `${process.env.REACT_APP_BACKEND_URL}/api`;

export default function LandingPage() {
  const navigate = useNavigate();
  const { user, token, logout } = useAuth();
  const [emails, setEmails] = useState("");
  const [isDragging, setIsDragging] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [file, setFile] = useState(null);

  const handleDragOver = useCallback((e) => {
    e.preventDefault();
    setIsDragging(true);
  }, []);

  const handleDragLeave = useCallback((e) => {
    e.preventDefault();
    setIsDragging(false);
  }, []);

  const handleDrop = useCallback((e) => {
    e.preventDefault();
    setIsDragging(false);
    const droppedFile = e.dataTransfer.files[0];
    if (droppedFile && droppedFile.name.endsWith('.csv')) {
      setFile(droppedFile);
      toast.success(`File "${droppedFile.name}" ready for upload`);
    } else {
      toast.error("Please upload a CSV file");
    }
  }, []);

  const handleFileSelect = (e) => {
    const selectedFile = e.target.files[0];
    if (selectedFile && selectedFile.name.endsWith('.csv')) {
      setFile(selectedFile);
      toast.success(`File "${selectedFile.name}" ready for upload`);
    } else {
      toast.error("Please select a CSV file");
    }
  };

  const handlePasteValidation = async () => {
    const emailList = emails
      .split(/[\n,;]/)
      .map(e => e.trim())
      .filter(e => e.includes('@'));

    if (emailList.length === 0) {
      toast.error("Please enter valid email addresses");
      return;
    }

    if (!user && emailList.length > 10) {
      toast.error("Sign up for free to validate more than 10 emails");
      navigate("/register");
      return;
    }

    setIsLoading(true);
    try {
      const headers = { "Content-Type": "application/json" };
      if (token) headers.Authorization = `Bearer ${token}`;
      
      const response = await axios.post(`${API}/validate/bulk`, { emails: emailList }, { headers });
      toast.success(`Validation started for ${emailList.length} emails`);
      navigate(`/results/${response.data.job_id}`);
    } catch (error) {
      toast.error(error.response?.data?.detail || "Failed to start validation");
    } finally {
      setIsLoading(false);
    }
  };

  const handleFileUpload = async () => {
    if (!file) {
      toast.error("Please select a file first");
      return;
    }

    if (!user) {
      toast.error("Sign up for free to upload files");
      navigate("/register");
      return;
    }

    setIsLoading(true);
    try {
      const formData = new FormData();
      formData.append('file', file);
      
      const headers = {};
      if (token) headers.Authorization = `Bearer ${token}`;
      
      const response = await axios.post(`${API}/validate/upload`, formData, {
        headers: { ...headers, 'Content-Type': 'multipart/form-data' }
      });
      toast.success(`Validation started for ${response.data.total_emails} emails`);
      navigate(`/results/${response.data.job_id}`);
    } catch (error) {
      toast.error(error.response?.data?.detail || "Failed to upload file");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen">
      {/* Header */}
      <header className="glass-header sticky top-0 z-50 py-4">
        <div className="max-w-7xl mx-auto px-6 md:px-12 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-indigo-600 flex items-center justify-center">
              <Mail className="w-5 h-5 text-white" />
            </div>
            <span className="text-xl font-bold text-slate-900" style={{ fontFamily: 'Manrope' }}>
              VerifyMail
            </span>
          </div>
          <nav className="hidden md:flex items-center gap-8">
            <a href="#features" className="text-slate-600 hover:text-slate-900 transition-colors text-sm font-medium">
              Features
            </a>
            <Link to="/pricing" className="text-slate-600 hover:text-slate-900 transition-colors text-sm font-medium">
              Pricing
            </Link>
          </nav>
          <div className="flex items-center gap-3">
            {user ? (
              <>
                <Link to="/dashboard">
                  <Button variant="outline" size="sm" className="gap-2">
                    <User className="w-4 h-4" />
                    Dashboard
                  </Button>
                </Link>
                <Button variant="ghost" size="sm" onClick={logout}>Logout</Button>
              </>
            ) : (
              <>
                <Link to="/login">
                  <Button variant="ghost" size="sm">Sign in</Button>
                </Link>
                <Link to="/register">
                  <Button size="sm" className="bg-indigo-600 hover:bg-indigo-700">Sign up free</Button>
                </Link>
              </>
            )}
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <section className="relative py-20 md:py-28 hero-glow">
        <div className="absolute inset-0 noise-texture pointer-events-none" />
        <div className="max-w-7xl mx-auto px-6 md:px-12">
          <div className="grid lg:grid-cols-2 gap-16 items-center">
            {/* Left Column - Text */}
            <div className="fade-in">
              <h1 
                className="text-4xl sm:text-5xl lg:text-6xl font-extrabold text-slate-900 leading-tight"
                style={{ fontFamily: 'Manrope' }}
              >
                Validate emails.
                <br />
                <span className="text-indigo-600">Keep the good.</span>
              </h1>
              <p className="mt-6 text-lg text-slate-600 max-w-lg leading-relaxed">
                Advanced bulk email validation with SMTP verification. 
                Separate active emails from junk in seconds.
              </p>
              <div className="mt-8 flex flex-wrap gap-4">
                <div className="flex items-center gap-2 text-sm text-slate-600">
                  <CheckCircle2 className="w-4 h-4 text-emerald-500" />
                  <span>Format validation</span>
                </div>
                <div className="flex items-center gap-2 text-sm text-slate-600">
                  <CheckCircle2 className="w-4 h-4 text-emerald-500" />
                  <span>MX record lookup</span>
                </div>
                <div className="flex items-center gap-2 text-sm text-slate-600">
                  <CheckCircle2 className="w-4 h-4 text-emerald-500" />
                  <span>SMTP verification</span>
                </div>
                <div className="flex items-center gap-2 text-sm text-slate-600">
                  <CheckCircle2 className="w-4 h-4 text-emerald-500" />
                  <span>Disposable detection</span>
                </div>
              </div>
            </div>

            {/* Right Column - Upload Card */}
            <div className="fade-in fade-in-delay-2">
              <Card className="bg-white border border-slate-100 shadow-xl rounded-2xl overflow-hidden">
                <CardContent className="p-0">
                  <Tabs defaultValue="paste" className="w-full">
                    <TabsList className="w-full rounded-none border-b bg-slate-50/50 p-0 h-auto">
                      <TabsTrigger 
                        value="paste" 
                        className="flex-1 rounded-none border-b-2 border-transparent data-[state=active]:border-indigo-600 data-[state=active]:bg-white py-4 text-sm font-medium"
                        data-testid="paste-tab"
                      >
                        <FileText className="w-4 h-4 mr-2" />
                        Paste Emails
                      </TabsTrigger>
                      <TabsTrigger 
                        value="upload"
                        className="flex-1 rounded-none border-b-2 border-transparent data-[state=active]:border-indigo-600 data-[state=active]:bg-white py-4 text-sm font-medium"
                        data-testid="upload-tab"
                      >
                        <Upload className="w-4 h-4 mr-2" />
                        Upload CSV
                      </TabsTrigger>
                    </TabsList>

                    <TabsContent value="paste" className="p-6 mt-0">
                      <Textarea
                        data-testid="email-textarea"
                        placeholder="Enter emails (one per line, comma or semicolon separated)&#10;&#10;example@domain.com&#10;another@email.com"
                        className="min-h-[200px] font-mono text-sm resize-none border-slate-200 focus:border-indigo-500 focus:ring-indigo-100"
                        value={emails}
                        onChange={(e) => setEmails(e.target.value)}
                      />
                      <Button 
                        data-testid="validate-paste-btn"
                        className="w-full mt-4 bg-indigo-600 hover:bg-indigo-700 text-white h-12 text-base font-semibold rounded-xl shadow-sm hover:shadow-md transition-all"
                        onClick={handlePasteValidation}
                        disabled={isLoading || !emails.trim()}
                      >
                        {isLoading ? (
                          <span className="flex items-center gap-2">
                            <svg className="animate-spin h-5 w-5" viewBox="0 0 24 24">
                              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                            </svg>
                            Processing...
                          </span>
                        ) : (
                          <span className="flex items-center gap-2">
                            <Zap className="w-5 h-5" />
                            Validate Emails
                          </span>
                        )}
                      </Button>
                    </TabsContent>

                    <TabsContent value="upload" className="p-6 mt-0">
                      <div
                        data-testid="dropzone"
                        className={`dropzone ${isDragging ? 'active' : ''}`}
                        onDragOver={handleDragOver}
                        onDragLeave={handleDragLeave}
                        onDrop={handleDrop}
                        onClick={() => document.getElementById('file-input').click()}
                      >
                        <input
                          id="file-input"
                          type="file"
                          accept=".csv"
                          className="hidden"
                          onChange={handleFileSelect}
                          data-testid="file-input"
                        />
                        <Upload className={`w-12 h-12 mx-auto mb-4 ${isDragging ? 'text-indigo-600' : 'text-slate-400'}`} />
                        <p className="text-slate-600 font-medium">
                          {file ? file.name : 'Drop your CSV file here'}
                        </p>
                        <p className="text-slate-400 text-sm mt-2">
                          or click to browse
                        </p>
                      </div>
                      <Button 
                        data-testid="validate-upload-btn"
                        className="w-full mt-4 bg-indigo-600 hover:bg-indigo-700 text-white h-12 text-base font-semibold rounded-xl shadow-sm hover:shadow-md transition-all"
                        onClick={handleFileUpload}
                        disabled={isLoading || !file}
                      >
                        {isLoading ? (
                          <span className="flex items-center gap-2">
                            <svg className="animate-spin h-5 w-5" viewBox="0 0 24 24">
                              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                            </svg>
                            Uploading...
                          </span>
                        ) : (
                          <span className="flex items-center gap-2">
                            <Upload className="w-5 h-5" />
                            Upload & Validate
                          </span>
                        )}
                      </Button>
                    </TabsContent>
                  </Tabs>
                </CardContent>
              </Card>
            </div>
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section id="features" className="py-20 bg-white">
        <div className="max-w-7xl mx-auto px-6 md:px-12">
          <div className="text-center mb-16">
            <h2 
              className="text-3xl md:text-4xl font-bold text-slate-900"
              style={{ fontFamily: 'Manrope' }}
            >
              Advanced Email Validation
            </h2>
            <p className="mt-4 text-slate-600 max-w-2xl mx-auto">
              Our multi-layer verification ensures you only keep valid, deliverable emails
            </p>
          </div>

          <div className="grid md:grid-cols-3 gap-8">
            <Card className="metric-card bg-white border border-slate-100 shadow-sm rounded-xl p-6">
              <CardContent className="p-0">
                <div className="w-12 h-12 rounded-xl bg-emerald-50 flex items-center justify-center mb-4">
                  <CheckCircle2 className="w-6 h-6 text-emerald-600" />
                </div>
                <h3 className="text-lg font-semibold text-slate-900" style={{ fontFamily: 'Manrope' }}>
                  Valid Emails
                </h3>
                <p className="mt-2 text-slate-600 text-sm leading-relaxed">
                  Emails that pass all checks: format, domain, MX records, and SMTP verification.
                </p>
              </CardContent>
            </Card>

            <Card className="metric-card bg-white border border-slate-100 shadow-sm rounded-xl p-6">
              <CardContent className="p-0">
                <div className="w-12 h-12 rounded-xl bg-rose-50 flex items-center justify-center mb-4">
                  <XCircle className="w-6 h-6 text-rose-600" />
                </div>
                <h3 className="text-lg font-semibold text-slate-900" style={{ fontFamily: 'Manrope' }}>
                  Invalid Emails
                </h3>
                <p className="mt-2 text-slate-600 text-sm leading-relaxed">
                  Emails that fail validation: bad format, non-existent domains, or dead mailboxes.
                </p>
              </CardContent>
            </Card>

            <Card className="metric-card bg-white border border-slate-100 shadow-sm rounded-xl p-6">
              <CardContent className="p-0">
                <div className="w-12 h-12 rounded-xl bg-amber-50 flex items-center justify-center mb-4">
                  <AlertTriangle className="w-6 h-6 text-amber-600" />
                </div>
                <h3 className="text-lg font-semibold text-slate-900" style={{ fontFamily: 'Manrope' }}>
                  Risky Emails
                </h3>
                <p className="mt-2 text-slate-600 text-sm leading-relaxed">
                  Disposable emails or those with uncertain deliverability status.
                </p>
              </CardContent>
            </Card>
          </div>
        </div>
      </section>

      {/* How It Works */}
      <section id="how-it-works" className="py-20 bg-slate-50">
        <div className="max-w-7xl mx-auto px-6 md:px-12">
          <div className="text-center mb-16">
            <h2 
              className="text-3xl md:text-4xl font-bold text-slate-900"
              style={{ fontFamily: 'Manrope' }}
            >
              How It Works
            </h2>
          </div>

          <div className="grid md:grid-cols-4 gap-6">
            {[
              { icon: FileText, title: "Upload", desc: "Paste emails or upload CSV" },
              { icon: Zap, title: "Process", desc: "Multi-layer validation runs" },
              { icon: Shield, title: "Verify", desc: "SMTP checks mailbox existence" },
              { icon: Clock, title: "Results", desc: "Get categorized results instantly" }
            ].map((step, i) => (
              <div key={i} className="text-center">
                <div className="w-16 h-16 rounded-2xl bg-indigo-100 flex items-center justify-center mx-auto mb-4">
                  <step.icon className="w-7 h-7 text-indigo-600" />
                </div>
                <h3 className="font-semibold text-slate-900" style={{ fontFamily: 'Manrope' }}>
                  {step.title}
                </h3>
                <p className="mt-2 text-slate-600 text-sm">{step.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="py-8 bg-white border-t border-slate-100">
        <div className="max-w-7xl mx-auto px-6 md:px-12 text-center">
          <p className="text-slate-500 text-sm">
            © 2025 VerifyMail. Built for clean email lists.
          </p>
        </div>
      </footer>
    </div>
  );
}
