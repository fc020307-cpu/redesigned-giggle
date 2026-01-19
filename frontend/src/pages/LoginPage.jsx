import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useAuth } from "@/context/AuthContext";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Mail } from "lucide-react";

export default function LoginPage() {
  const navigate = useNavigate();
  const { login } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      await login(email, password);
      toast.success("Login successful!");
      navigate("/dashboard");
    } catch (err) {
      toast.error(err.message);
    }
    setLoading(false);
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-50 px-4">
      <Card className="w-full max-w-md" data-testid="login-card">
        <CardHeader className="text-center">
          <div className="flex justify-center mb-4">
            <div className="w-12 h-12 rounded-xl bg-indigo-600 flex items-center justify-center">
              <Mail className="w-6 h-6 text-white" />
            </div>
          </div>
          <CardTitle className="text-2xl" style={{ fontFamily: 'Manrope' }}>Welcome back</CardTitle>
          <p className="text-slate-500 text-sm mt-2">Sign in to your account</p>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="text-sm font-medium text-slate-700">Email</label>
              <Input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="you@example.com"
                required
                data-testid="login-email"
              />
            </div>
            <div>
              <label className="text-sm font-medium text-slate-700">Password</label>
              <Input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                required
                data-testid="login-password"
              />
            </div>
            <Button
              type="submit"
              className="w-full bg-indigo-600 hover:bg-indigo-700"
              disabled={loading}
              data-testid="login-submit"
            >
              {loading ? "Signing in..." : "Sign in"}
            </Button>
          </form>
          <p className="text-center text-sm text-slate-500 mt-4">
            Don't have an account?{" "}
            <Link to="/register" className="text-indigo-600 hover:underline">Sign up</Link>
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
