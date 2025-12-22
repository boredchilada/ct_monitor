import os
import logging
from typing import Set, Dict
from datetime import datetime, timezone
from langchain_core.prompts import PromptTemplate
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_openai import ChatOpenAI

class DomainAnalyzer:
    def __init__(self, config: Dict, output_dir: str):
        self.config = config
        self.output_dir = output_dir
        self.log = logging.getLogger(__name__)

    def is_suspicious(self, domain: str) -> bool:
        """Checks if a domain contains any monitored keywords."""
        keywords = self.config.get('monitored_keywords', [])
        if not keywords:
            return False
        return any(keyword in domain for keyword in keywords)

    def analyze_domains_for_phishing(self, domains: Set[str]):
        """Analyzes a list of domains for potential phishing threats using an LLM."""
        self.log.info("--- AI Phishing Analysis Start ---")

        ai_provider = self.config.get("ai_provider", "google").lower()
        model_name = self.config.get("ai_model")
        batch_size = self.config.get("ai_batch_size", 100)
        
        llm = None

        if ai_provider == "google":
            if not model_name:
                model_name = "gemini-2.5-flash"
            
            api_key_name = "GOOGLE_API_KEY"
            if not os.getenv(api_key_name):
                self.log.error(f"{api_key_name} not found in environment or .env file.")
                return

            try:
                llm = ChatGoogleGenerativeAI(model=model_name)
            except Exception as e:
                self.log.error(f"Error initializing Google LLM: {e}")
                return

        elif ai_provider == "openrouter":
            if not model_name:
                model_name = "google/gemini-2.0-flash-001" # Default OpenRouter model
            
            api_key_name = "OPENROUTER_API_KEY"
            if not os.getenv(api_key_name):
                self.log.error(f"{api_key_name} not found in environment or .env file.")
                return

            try:
                llm = ChatOpenAI(
                    model=model_name,
                    api_key=os.getenv(api_key_name), # type: ignore
                    base_url="https://openrouter.ai/api/v1",
                    default_headers={
                        "HTTP-Referer": "https://github.com/boredchilada/CT_Monitor",
                        "X-Title": "CT Monitor"
                    }
                )
            except Exception as e:
                self.log.error(f"Error initializing OpenRouter LLM: {e}")
                return
        else:
            self.log.error(f"Unknown AI provider: {ai_provider}")
            return

        # Users can customize this prompt for better results.
        prompt_template = PromptTemplate.from_template(
            """
            You are an expert Cyber Threat Intelligence Analyst specializing in phishing detection and brand protection.
            Your task is to analyze the following list of newly registered domain names to identify potential phishing threats, specifically focusing on brand impersonation and social engineering tactics.

            For each domain, evaluate the following criteria:
            1. **Brand Impersonation**: Does the domain mimic a known brand (e.g., PayPal, Google, Microsoft, Apple, Banks, Crypto exchanges) using exact matches, typosquatting (e.g., 'g0ogle'), or combosquatting (e.g., 'paypal-login')?
            2. **Suspicious Keywords**: Does it contain high-risk keywords often used in phishing (e.g., 'login', 'verify', 'secure', 'update', 'account', 'support', 'billing')?
            3. **TLD Reputation**: Is it using a TLD commonly associated with abuse (though not a sole indicator)?
            4. **Entropy/Randomness**: Does the domain look like a DGA (Domain Generation Algorithm) or random characters?
            5. **Keyword Stuffing / Subdomain Nesting**: Does the domain contain an excessive number of unrelated brand names or keywords nested in subdomains? These are often automated spam/parking domains and should be treated as NOISE.
               - **Example of NOISE**: `pochta.pay.pochtabank.pochta.sberbank.nalozhka.sberbank.kwid9.usepay.xyz` (Too many brands, clearly automated)
               - **Example of NOISE**: `sbermarket.pay.pochtabank.blablacar.avito.tbgld43s9s18dmr1zpdvpux9j189mkd4.poc.purepilatesladera.com` (Excessive nesting, unrelated brands)

            Classify each domain into one of two categories:
            - **SUSPICIOUS**: High confidence of malicious intent or impersonation. Provide a brief, specific reason (e.g., "Impersonates PayPal with 'verify' keyword").
            - **SAFE**: Likely benign, unrelated to common phishing targets, insufficient evidence to flag, OR classified as "keyword stuffing" noise.

            **Output Format:**
            Respond strictly with two lists in the following format. Do not include any conversational text.

            SUSPICIOUS:
            - domain1: reason
            - domain2: reason

            SAFE:
            - domain3
            - domain4

            If a list is empty, leave it blank after the heading.

            Domain list:
            {domains}
            """
        )
        chain = prompt_template | llm
        
        domain_list = list(domains)
        all_suspicious_results = []
        all_safe_domains = set()

        for i in range(0, len(domain_list), batch_size):
            batch = domain_list[i:i + batch_size]
            domain_list_str = "\n".join(batch)
            
            self.log.info(f"Analyzing batch {i//batch_size + 1}/{(len(domain_list) + batch_size - 1)//batch_size}...")
            
            try:
                response = chain.invoke({"domains": domain_list_str})
                analysis_result = str(response.content).strip()
                
                suspicious_part = ""
                safe_part = ""

                if "SUSPICIOUS:" in analysis_result and "SAFE:" in analysis_result:
                    suspicious_part = analysis_result.split("SUSPICIOUS:")[1].split("SAFE:")[0].strip()
                    safe_part = analysis_result.split("SAFE:")[1].strip()
                elif "SUSPICIOUS:" in analysis_result:
                    suspicious_part = analysis_result.split("SUSPICIOUS:")[1].strip()
                elif "SAFE:" in analysis_result:
                    safe_part = analysis_result.split("SAFE:")[1].strip()

                if suspicious_part:
                    suspicious_lines = [line.strip() for line in suspicious_part.split('\n') if line.strip() and line.strip().startswith('-')]
                    all_suspicious_results.extend(suspicious_lines)
                
                if safe_part:
                    safe_lines = [line.strip().lstrip('- ').strip() for line in safe_part.split('\n') if line.strip() and line.strip().startswith('-')]
                    all_safe_domains.update(safe_lines)

            except Exception as e:
                self.log.error(f"Error analyzing batch: {e}")

        # Save suspicious domains
        output_file_suspicious = os.path.join(self.output_dir, "phishing_analysis.txt")
        try:
            with open(output_file_suspicious, 'a', encoding='utf-8') as f:
                f.write(f"\n\n--- Analysis Results from {datetime.now(timezone.utc).isoformat()} ---\n")
                if all_suspicious_results:
                    for result in all_suspicious_results:
                        f.write(result + "\n")
                else:
                    f.write("No suspicious domains found in any batch.\n")
            self.log.info(f"AI analysis complete. Suspicious domains saved to {output_file_suspicious}")
        except IOError as e:
            self.log.error(f"Error saving AI analysis to {output_file_suspicious}: {e}")

        # Save safe domains
        output_file_safe = os.path.join(self.output_dir, "safe_domains.txt")
        try:
            with open(output_file_safe, 'a', encoding='utf-8') as f:
                f.write(f"\n# Safe domains discovered at {datetime.now(timezone.utc).isoformat()}\n")
                if all_safe_domains:
                    for domain in sorted(list(all_safe_domains)):
                        f.write(f"{domain}\n")
                else:
                    f.write("No new safe domains identified in this run.\n")
            self.log.info(f"Safe domains saved to {output_file_safe}")
        except IOError as e:
            self.log.error(f"Error saving safe domains to {output_file_safe}: {e}")

        self.log.info("--- AI Phishing Analysis End ---")