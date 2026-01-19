import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useAuth } from "@/context/AuthContext";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { CheckCircle2, Mail, Loader2 } from "lucide-react";

const API = process.env.REACT_APP_BACKEND_URL;

export default function PaymentSuccessPage() {
  const [searchParams] = useSearchParams();
  const { token, refreshUser } = useAuth();
  const [status, setStatus] = useState("checking");
  const [attempts, setAttempts] = useState(0);

  const sessionId = searchParams.get("session_id");

  useEffect(() => {
    if (!sessionId || !token) return;

    const checkStatus = async () => {
      try {
        const res = await fetch(`${API}/api/checkout/status/${sessionId}`, {
          headers: { Authorization: `Bearer ${token}` }
        });
        const data = await res.json();

        if (data.payment_status === "paid") {
          setStatus("success");
          refreshUser();
        } else if (data.status === "expired") {
          setStatus("expired");
        } else if (attempts < 10) {
          setTimeout(() => setAttempts(a => a + 1), 2000);
        } else {
          setStatus("timeout");
        }
      } catch {
        if (attempts < 10) {
          setTimeout(() => setAttempts(a => a + 1), 2000);
        } else {
          setStatus("error");
        }
      }
    };

    checkStatus();
  }, [sessionId, token, attempts, refreshUser]);

  return (
    <div className="min-h-screen bg-slate-50 flex items-center justify-center px-4">
      <Card className="w-full max-w-md text-center">
        <CardContent className="py-12">
          {status === "checking" && (
            <>
              <Loader2 className="w-16 h-16 text-indigo-600 mx-auto mb-6 animate-spin" />
              <h1 className="text-2xl font-bold mb-2" style={{ fontFamily: 'Manrope' }}>
                Processing Payment...
              </h1>
              <p className="text-slate-500">Please wait while we confirm your payment.</p>
            </>
          )}

          {status === "success" && (
            <>
              <div className="w-20 h-20 rounded-full bg-emerald-100 flex items-center justify-center mx-auto mb-6">
                <CheckCircle2 className="w-10 h-10 text-emerald-600" />
              </div>
              <h1 className="text-2xl font-bold mb-2" style={{ fontFamily: 'Manrope' }}>
                Payment Successful!
              </h1>
              <p className="text-slate-500 mb-6">Your plan has been upgraded. Start validating emails now!</p>
              <Link to="/dashboard">
                <Button className="bg-indigo-600 hover:bg-indigo-700">
                  Go to Dashboard
                </Button>
              </Link>
            </>
          )}

          {(status === "expired" || status === "timeout" || status === "error") && (
            <>
              <div className="w-20 h-20 rounded-full bg-amber-100 flex items-center justify-center mx-auto mb-6">
                <Mail className="w-10 h-10 text-amber-600" />
              </div>
              <h1 className="text-2xl font-bold mb-2" style={{ fontFamily: 'Manrope' }}>
                {status === "expired" ? "Session Expired" : "Verification Issue"}
              </h1>
              <p className="text-slate-500 mb-6">
                {status === "expired" 
                  ? "Your payment session has expired. Please try again."
                  : "We couldn't verify your payment. If you were charged, please contact support."}
              </p>
              <div className="flex gap-3 justify-center">
                <Link to="/pricing">
                  <Button variant="outline">Try Again</Button>
                </Link>
                <Link to="/dashboard">
                  <Button className="bg-indigo-600 hover:bg-indigo-700">Dashboard</Button>
                </Link>
              </div>
            </>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
