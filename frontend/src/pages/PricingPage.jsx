import { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import { useAuth } from "@/context/AuthContext";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Check, Mail, Zap, Crown, Star } from "lucide-react";

const API = process.env.REACT_APP_BACKEND_URL;

export default function PricingPage() {
  const { user, token } = useAuth();
  const [plans, setPlans] = useState({});
  const [loading, setLoading] = useState(null);

  useEffect(() => {
    fetch(`${API}/api/plans`).then(r => r.json()).then(setPlans);
  }, []);

  const handleSubscribe = async (planId) => {
    if (!user) {
      window.location.href = "/register";
      return;
    }
    
    setLoading(planId);
    try {
      const res = await fetch(`${API}/api/checkout/create`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`
        },
        body: JSON.stringify({
          plan_id: planId,
          origin_url: window.location.origin
        })
      });
      
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Failed to create checkout");
      
      window.location.href = data.url;
    } catch (err) {
      toast.error(err.message);
    }
    setLoading(null);
  };

  const planIcons = { free: Star, basic: Zap, pro: Crown };

  return (
    <div className="min-h-screen bg-slate-50">
      {/* Header */}
      <header className="bg-white border-b py-4">
        <div className="max-w-7xl mx-auto px-6 flex items-center justify-between">
          <Link to="/" className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-indigo-600 flex items-center justify-center">
              <Mail className="w-5 h-5 text-white" />
            </div>
            <span className="text-xl font-bold" style={{ fontFamily: 'Manrope' }}>VerifyMail</span>
          </Link>
          <div className="flex gap-4">
            {user ? (
              <Link to="/dashboard">
                <Button variant="outline">Dashboard</Button>
              </Link>
            ) : (
              <>
                <Link to="/login"><Button variant="ghost">Sign in</Button></Link>
                <Link to="/register"><Button className="bg-indigo-600 hover:bg-indigo-700">Sign up</Button></Link>
              </>
            )}
          </div>
        </div>
      </header>

      {/* Pricing Section */}
      <section className="py-20">
        <div className="max-w-7xl mx-auto px-6">
          <div className="text-center mb-16">
            <h1 className="text-4xl font-bold text-slate-900" style={{ fontFamily: 'Manrope' }}>
              Simple, transparent pricing
            </h1>
            <p className="mt-4 text-lg text-slate-600">
              Choose the plan that fits your needs
            </p>
          </div>

          <div className="grid md:grid-cols-3 gap-8 max-w-5xl mx-auto">
            {Object.entries(plans).map(([id, plan]) => {
              const Icon = planIcons[id] || Star;
              const isCurrentPlan = user?.plan === id;
              const isPopular = id === "basic";

              return (
                <Card 
                  key={id} 
                  className={`relative ${isPopular ? 'border-indigo-500 border-2 shadow-lg' : ''}`}
                  data-testid={`plan-${id}`}
                >
                  {isPopular && (
                    <Badge className="absolute -top-3 left-1/2 -translate-x-1/2 bg-indigo-600">
                      Most Popular
                    </Badge>
                  )}
                  <CardHeader className="text-center pb-4">
                    <div className={`w-12 h-12 rounded-xl mx-auto mb-4 flex items-center justify-center ${
                      id === 'pro' ? 'bg-amber-100' : id === 'basic' ? 'bg-indigo-100' : 'bg-slate-100'
                    }`}>
                      <Icon className={`w-6 h-6 ${
                        id === 'pro' ? 'text-amber-600' : id === 'basic' ? 'text-indigo-600' : 'text-slate-600'
                      }`} />
                    </div>
                    <CardTitle style={{ fontFamily: 'Manrope' }}>{plan.name}</CardTitle>
                    <div className="mt-4">
                      <span className="text-4xl font-bold text-slate-900">${plan.price}</span>
                      {plan.price > 0 && <span className="text-slate-500">/month</span>}
                    </div>
                    <p className="text-sm text-slate-500 mt-2">
                      {plan.verifications_per_month.toLocaleString()} verifications/month
                    </p>
                  </CardHeader>
                  <CardContent>
                    <ul className="space-y-3 mb-6">
                      {plan.features?.map((feature, i) => (
                        <li key={i} className="flex items-center gap-2 text-sm">
                          <Check className="w-4 h-4 text-emerald-500" />
                          <span className="text-slate-600">{feature}</span>
                        </li>
                      ))}
                    </ul>
                    {isCurrentPlan ? (
                      <Button className="w-full" variant="outline" disabled>
                        Current Plan
                      </Button>
                    ) : id === "free" ? (
                      <Link to="/register">
                        <Button className="w-full" variant="outline">
                          Get Started
                        </Button>
                      </Link>
                    ) : (
                      <Button
                        className={`w-full ${isPopular ? 'bg-indigo-600 hover:bg-indigo-700' : ''}`}
                        variant={isPopular ? "default" : "outline"}
                        onClick={() => handleSubscribe(id)}
                        disabled={loading === id}
                        data-testid={`subscribe-${id}`}
                      >
                        {loading === id ? "Processing..." : "Subscribe"}
                      </Button>
                    )}
                  </CardContent>
                </Card>
              );
            })}
          </div>
        </div>
      </section>
    </div>
  );
}
