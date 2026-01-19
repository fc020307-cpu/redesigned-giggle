import { useState, useCallback } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useAuth } from "@/context/AuthContext";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { 
  Mail, Upload, LogOut, Zap, Settings, CreditCard, 
  CheckCircle2, XCircle, AlertTriangle, User
} from "lucide-react";

const API = process.env.REACT_APP_BACKEND_URL;

export default function DashboardPage() {
  const navigate = useNavigate();
  const { user, token, logout, refreshUser } = useAuth();
  const [emails, setEmails] = useState("");
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [isDragging, setIsDragging] = useState(false);

  const usagePercent = user ? (user.verifications_used / user.verifications_limit) * 100 : 0;
  const remaining = user ? user.verifications_limit - user.verifications_used : 0;

  const handleValidate = async () => {
    const emailList = emails.split(/[\n,;]/).map(e => e.trim()).filter(e => e.includes('@'));
    
    if (emailList.length === 0) {
      toast.error("Please enter valid email addresses");
      return;
    }

    if (emailList.length > remaining) {
      toast.error(`You only have ${remaining} verifications remaining. Please upgrade.`);
      return;
    }

    setLoading(true);
    try {
      const res = await fetch(`${API}/api/validate/bulk`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`
        },
        body: JSON.stringify({ emails: emailList })
      });
      
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Validation failed");
      
      toast.success(`Validating ${emailList.length} emails...`);
      refreshUser();
      navigate(`/results/${data.job_id}`);
    } catch (err) {
      toast.error(err.message);
    }
    setLoading(false);
  };

  const handleFileUpload = async () => {
    if (!file) {
      toast.error("Please select a file");
      return;
    }

    setLoading(true);
    try {
      const formData = new FormData();
      formData.append('file', file);
      
      const res = await fetch(`${API}/api/validate/upload`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
        body: formData
      });
      
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Upload failed");
      
      toast.success(`Validating ${data.total_emails} emails...`);
      refreshUser();
      navigate(`/results/${data.job_id}`);
    } catch (err) {
      toast.error(err.message);
    }
    setLoading(false);
  };

  const handleDrop = useCallback((e) => {
    e.preventDefault();
    setIsDragging(false);
    const droppedFile = e.dataTransfer.files[0];
    if (droppedFile?.name.endsWith('.csv')) {
      setFile(droppedFile);
      toast.success(`File "${droppedFile.name}" ready`);
    } else {
      toast.error("Please upload a CSV file");
    }
  }, []);

  const handleLogout = () => {
    logout();
    navigate("/");
  };

  const planColors = {
    free: "bg-slate-100 text-slate-700",
    basic: "bg-indigo-100 text-indigo-700",
    pro: "bg-amber-100 text-amber-700"
  };

  return (
    <div className="min-h-screen bg-slate-50">
      {/* Header */}
      <header className="bg-white border-b py-4 sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-6 flex items-center justify-between">
          <Link to="/" className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-indigo-600 flex items-center justify-center">
              <Mail className="w-5 h-5 text-white" />
            </div>
            <span className="text-xl font-bold" style={{ fontFamily: 'Manrope' }}>VerifyMail</span>
          </Link>
          <div className="flex items-center gap-4">
            <Link to="/pricing">
              <Button variant="ghost" size="sm" className="gap-2">
                <CreditCard className="w-4 h-4" />
                Upgrade
              </Button>
            </Link>
            <div className="flex items-center gap-2 px-3 py-1.5 bg-slate-100 rounded-full">
              <User className="w-4 h-4 text-slate-500" />
              <span className="text-sm font-medium text-slate-700">{user?.name}</span>
              <span className={`text-xs px-2 py-0.5 rounded-full ${planColors[user?.plan] || planColors.free}`}>
                {user?.plan?.toUpperCase()}
              </span>
            </div>
            <Button variant="ghost" size="sm" onClick={handleLogout} data-testid="logout-btn">
              <LogOut className="w-4 h-4" />
            </Button>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-6 py-8">
        {/* Usage Stats */}
        <div className="grid md:grid-cols-4 gap-4 mb-8">
          <Card>
            <CardContent className="py-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-slate-500">Plan</p>
                  <p className="text-xl font-bold capitalize" style={{ fontFamily: 'Manrope' }}>{user?.plan}</p>
                </div>
                <Settings className="w-8 h-8 text-slate-300" />
              </div>
            </CardContent>
          </Card>
          
          <Card>
            <CardContent className="py-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-slate-500">Used</p>
                  <p className="text-xl font-bold" style={{ fontFamily: 'Manrope' }}>{user?.verifications_used || 0}</p>
                </div>
                <CheckCircle2 className="w-8 h-8 text-emerald-300" />
              </div>
            </CardContent>
          </Card>
          
          <Card>
            <CardContent className="py-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-slate-500">Remaining</p>
                  <p className="text-xl font-bold" style={{ fontFamily: 'Manrope' }}>{remaining}</p>
                </div>
                <Zap className="w-8 h-8 text-amber-300" />
              </div>
            </CardContent>
          </Card>
          
          <Card>
            <CardContent className="py-4">
              <div>
                <p className="text-sm text-slate-500 mb-2">Usage</p>
                <Progress value={usagePercent} className="h-2" />
                <p className="text-xs text-slate-400 mt-1">{Math.round(usagePercent)}% used</p>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Low usage warning */}
        {remaining < 10 && (
          <Card className="mb-8 border-amber-200 bg-amber-50">
            <CardContent className="py-4 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <AlertTriangle className="w-5 h-5 text-amber-600" />
                <span className="text-amber-800">You have {remaining} verifications left.</span>
              </div>
              <Link to="/pricing">
                <Button size="sm" className="bg-amber-600 hover:bg-amber-700">Upgrade Now</Button>
              </Link>
            </CardContent>
          </Card>
        )}

        {/* Validation Form */}
        <div className="grid lg:grid-cols-2 gap-8">
          {/* Paste Emails */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2" style={{ fontFamily: 'Manrope' }}>
                <Mail className="w-5 h-5 text-indigo-600" />
                Paste Emails
              </CardTitle>
            </CardHeader>
            <CardContent>
              <Textarea
                placeholder="Enter emails (one per line, comma or semicolon separated)&#10;&#10;example@domain.com&#10;another@email.com"
                className="min-h-[200px] font-mono text-sm"
                value={emails}
                onChange={(e) => setEmails(e.target.value)}
                data-testid="email-textarea"
              />
              <Button
                className="w-full mt-4 bg-indigo-600 hover:bg-indigo-700"
                onClick={handleValidate}
                disabled={loading || !emails.trim()}
                data-testid="validate-btn"
              >
                {loading ? "Processing..." : "Validate Emails"}
              </Button>
            </CardContent>
          </Card>

          {/* Upload CSV */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2" style={{ fontFamily: 'Manrope' }}>
                <Upload className="w-5 h-5 text-indigo-600" />
                Upload CSV
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div
                className={`border-2 border-dashed rounded-xl p-12 text-center cursor-pointer transition-all ${
                  isDragging ? 'border-indigo-500 bg-indigo-50' : 'border-slate-300 hover:border-indigo-400'
                }`}
                onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
                onDragLeave={() => setIsDragging(false)}
                onDrop={handleDrop}
                onClick={() => document.getElementById('csv-input').click()}
                data-testid="dropzone"
              >
                <input
                  id="csv-input"
                  type="file"
                  accept=".csv"
                  className="hidden"
                  onChange={(e) => {
                    const f = e.target.files[0];
                    if (f) { setFile(f); toast.success(`File "${f.name}" ready`); }
                  }}
                />
                <Upload className={`w-10 h-10 mx-auto mb-3 ${isDragging ? 'text-indigo-600' : 'text-slate-400'}`} />
                <p className="text-slate-600 font-medium">{file ? file.name : 'Drop CSV here'}</p>
                <p className="text-slate-400 text-sm mt-1">or click to browse</p>
              </div>
              <Button
                className="w-full mt-4 bg-indigo-600 hover:bg-indigo-700"
                onClick={handleFileUpload}
                disabled={loading || !file}
                data-testid="upload-btn"
              >
                {loading ? "Uploading..." : "Upload & Validate"}
              </Button>
            </CardContent>
          </Card>
        </div>
      </main>
    </div>
  );
}
