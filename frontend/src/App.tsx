import { useCallback, useEffect, useState } from "react";
import type { BackendKind, IocType, Report } from "./lib/types";
import { InvestigatePanel } from "./components/investigate/InvestigatePanel";
import { FeedPanel } from "./components/feed/FeedPanel";
import { DashboardPanel } from "./components/dashboard/DashboardPanel";
import { LoginScreen } from "./components/auth/LoginScreen";
import { useInvestigation } from "./components/investigate/useInvestigation";
import { DashboardIcon, FeedIcon, SearchIcon } from "./components/ui/Icons";
import { fetchAuthStatus, logout } from "./lib/api";
import "./App.css";

type Tab = "dashboard" | "investigate" | "feed";

const PAGE: Record<Tab, { crumb: string[]; title: string }> = {
  dashboard: { crumb: ["Dashboard"], title: "Operations dashboard" },
  investigate: { crumb: ["Investigate", "Report"], title: "Investigation report" },
  feed: { crumb: ["Live feed"], title: "Live indicator feed" },
};

const MAX_HISTORY = 20;

export default function App() {
  const [tab, setTab] = useState<Tab>("dashboard");
  const [history, setHistory] = useState<Report[]>([]);
  const investigation = useInvestigation();

  // Auth gate: check status once on load.
  const [authReady, setAuthReady] = useState(false);
  const [authRequired, setAuthRequired] = useState(false);
  const [authed, setAuthed] = useState(false);

  useEffect(() => {
    fetchAuthStatus()
      .then((s) => {
        setAuthRequired(s.auth_required);
        setAuthed(s.authenticated);
      })
      .catch(() => {
        // If the status check fails, assume open access rather than locking out.
        setAuthRequired(false);
        setAuthed(true);
      })
      .finally(() => setAuthReady(true));
  }, []);

  const handleLogout = useCallback(async () => {
    await logout();
    setAuthed(false);
  }, []);

  // Record each completed report once, newest first (state lives in App so it
  // survives tab switches).
  const report = investigation.report;
  useEffect(() => {
    if (!report) return;
    setHistory((prev) => {
      if (prev[0] === report) return prev;
      return [report, ...prev.filter((r) => r !== report)].slice(0, MAX_HISTORY);
    });
  }, [report]);

  const investigateFromFeed = useCallback(
    (ioc: string, type: IocType, backend: BackendKind) => {
      investigation.start(ioc, type, backend);
      setTab("investigate");
    },
    [investigation],
  );

  const openReport = useCallback(
    (r: Report) => {
      investigation.show(r);
      setTab("investigate");
    },
    [investigation],
  );

  const page = PAGE[tab];

  if (!authReady) return null;
  if (authRequired && !authed) {
    return <LoginScreen onAuthed={() => setAuthed(true)} />;
  }

  return (
    <div className="app">
      <header className="appbar">
        <div className="appbar__brand">
          <span className="appbar__logo">TI</span>
          <span className="appbar__product">Threat Intel</span>
        </div>
        <div className="appbar__search">
          <SearchIcon width={16} height={16} />
          <span>Search indicators, reports, detections</span>
        </div>
        <div className="appbar__right">
          <span className="appbar__role">SOC · Tier 2</span>
          <span className="appbar__avatar">AK</span>
          {authRequired && (
            <button className="appbar__logout" onClick={handleLogout}>
              Sign out
            </button>
          )}
        </div>
      </header>

      <div className="app__body">
        <nav className="rail" aria-label="Primary">
          <div className="rail__heading">Operations</div>
          <RailRow
            icon={<DashboardIcon />}
            label="Dashboard"
            active={tab === "dashboard"}
            onClick={() => setTab("dashboard")}
          />
          <RailRow
            icon={<SearchIcon />}
            label="Investigate"
            active={tab === "investigate"}
            onClick={() => setTab("investigate")}
          />
          <RailRow
            icon={<FeedIcon />}
            label="Live feed"
            active={tab === "feed"}
            onClick={() => setTab("feed")}
          />
        </nav>

        <main className="content">
          <div className="content__crumb">
            {page.crumb.map((seg, i) => (
              <span
                key={seg}
                className={i === page.crumb.length - 1 ? "content__crumb-cur" : ""}
              >
                {i > 0 && <span className="content__crumb-sep">/</span>}
                {seg}
              </span>
            ))}
          </div>
          <h1 className="content__title">{page.title}</h1>

          {tab === "dashboard" && (
            <DashboardPanel
              history={history}
              onOpen={openReport}
              onInvestigate={() => setTab("investigate")}
            />
          )}
          {tab === "investigate" && (
            <InvestigatePanel investigation={investigation} />
          )}
          {tab === "feed" && <FeedPanel onInvestigate={investigateFromFeed} />}
        </main>
      </div>
    </div>
  );
}

interface RailRowProps {
  icon: React.ReactNode;
  label: string;
  active?: boolean;
  onClick?: () => void;
}

function RailRow({ icon, label, active, onClick }: RailRowProps) {
  return (
    <button
      className={`rail__row ${active ? "rail__row--active" : ""}`}
      onClick={onClick}
      aria-current={active ? "page" : undefined}
    >
      <span className="rail__icon">{icon}</span>
      {label}
    </button>
  );
}
