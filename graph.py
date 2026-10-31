"""Neo4j: red flags, known-bad domains, and memory of past scans."""
import os

from common import DEFAULT_RED_FLAGS


class Graph:
    def __init__(self):
        self.driver = None
        uri = os.getenv("NEO4J_URI", "").strip()
        if not uri:
            return
        try:
            from neo4j import GraphDatabase
            self.driver = GraphDatabase.driver(
                uri, auth=(os.getenv("NEO4J_USERNAME", "neo4j"), os.getenv("NEO4J_PASSWORD", "")))
            self.driver.verify_connectivity()
        except Exception as e:
            print(f"[neo4j] not connected ({e}); using built-in red flags")
            self.driver = None

    def _run(self, q, **params):
        with self.driver.session(database=os.getenv("NEO4J_DATABASE") or None) as s:
            return [r.data() for r in s.run(q, **params)]

    @property
    def online(self):
        return self.driver is not None

    # ---------- reads ----------
    def red_flags(self) -> dict:
        flags = {k: {"description": d, "weight": w} for k, (d, w) in DEFAULT_RED_FLAGS.items()}
        if self.online:
            try:
                for r in self._run("MATCH (f:RedFlag) RETURN f.key AS key, f.description AS d, f.weight AS w"):
                    flags[r["key"]] = {"description": r["d"], "weight": int(r["w"])}
            except Exception as e:
                print(f"[neo4j] red_flags failed: {e}")
        return flags

    def is_known_bad(self, *domains) -> bool:
        if not self.online:
            return False
        try:
            r = self._run(
                "MATCH (d:Domain) WHERE d.name IN $names AND (d.known_bad = true OR d.flagged_by_scan = true) "
                "RETURN count(d) AS n", names=[d for d in domains if d])
            return r[0]["n"] > 0
        except Exception as e:
            print(f"[neo4j] is_known_bad failed: {e}")
            return False

    def related_scans(self, url, brand, send_to_domains) -> list:
        """Earlier high-risk scans that impersonated the same brand or sent data to the same place."""
        if not self.online:
            return []
        try:
            return self._run(
                """
                MATCH (s:Scan) WHERE s.url <> $url AND s.score >= 60
                OPTIONAL MATCH (s)-[:IMPERSONATES]->(b:Brand)
                OPTIONAL MATCH (s)-[:SENDS_DATA_TO]->(t:Domain)
                WITH s, collect(DISTINCT b.name) AS brands, collect(DISTINCT t.name) AS targets
                WHERE ($brand IS NOT NULL AND $brand IN brands)
                   OR any(x IN targets WHERE x IN $targets)
                RETURN s.url AS url, s.score AS score, brands, targets
                ORDER BY s.score DESC LIMIT 5
                """, url=url, brand=brand, targets=list(send_to_domains))
        except Exception as e:
            print(f"[neo4j] related_scans failed: {e}")
            return []

    # ---------- writes ----------
    def save_scan(self, report: dict):
        if not self.online:
            return
        try:
            url, dom = report["url"], report["domain"]
            self._run(
                """
                MERGE (d:Domain {name:$dom})
                CREATE (s:Scan {url:$url, score:$score, verdict:$verdict, at:datetime()})
                MERGE (s)-[:ON_DOMAIN]->(d)
                WITH d SET d.flagged_by_scan = coalesce(d.flagged_by_scan,false) OR $score >= 80
                """, dom=dom, url=url, score=report["score"], verdict=report["verdict"])
            match_scan = "MATCH (s:Scan {url:$url}) WITH s ORDER BY s.at DESC LIMIT 1 "
            for key in [f["key"] for f in report.get("flags", [])]:
                self._run(match_scan + "MATCH (f:RedFlag {key:$k}) MERGE (s)-[:HAS_FLAG]->(f)", url=url, k=key)
            for t in report.get("data_targets", []):
                self._run(match_scan + "MERGE (x:DataType {name:$t}) MERGE (s)-[:ASKS_FOR]->(x)", url=url, t=t)
            if report.get("brand"):
                self._run(match_scan + "MERGE (b:Brand {name:$b}) MERGE (s)-[:IMPERSONATES]->(b)",
                          url=url, b=report["brand"])
            for t in report.get("send_to_domains", []):
                self._run(match_scan + "MERGE (x:Domain {name:$t}) MERGE (s)-[:SENDS_DATA_TO]->(x)", url=url, t=t)
        except Exception as e:
            print(f"[neo4j] save_scan failed: {e}")
