# target_bot.py
# ─────────────────────────────────────────────────────────────────────────────
# Target adapter classes — each class knows how to send a prompt to one
# specific type of chatbot and return its response as a plain string.
#
# The engine and orchestrator never communicate with targets directly; they
# always go through one of these adapters.  This keeps the scanning logic
# (what to send) completely separate from the interaction logic (how to send
# it), making it straightforward to add new target types without touching the
# rest of the codebase.
#
# Adapters in this file:
#   BaseTargetAdapter    – abstract contract every adapter must satisfy
#   SeleniumTargetAdapter – generic Selenium UI adapter for arbitrary web chatbots
#   GenericAPITarget      – HTTP POST adapter for any REST chatbot API
#   DeepSeekDemoTarget    – DeepSeek API adapter with demo-mode fabrication
#   DVLASeleniumTarget    – specialist Selenium adapter for the DVLA Streamlit chatbot
#                           (includes stability polling, multi-turn session reuse,
#                           and transient-state filtering)
# ─────────────────────────────────────────────────────────────────────────────

from abc import ABC, abstractmethod
from typing import Optional
import httpx
import logging
import time
import re

# Selenium imports — used by SeleniumTargetAdapter and DVLASeleniumTarget
# to automate a real Chrome browser for UI-based scanning.
from selenium.webdriver.chrome.webdriver import WebDriver as ChromeDriver
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager

from config import Config

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ─── Base adapter interface ───────────────────────────────────────────────────
# All adapters must implement send_prompt().  Defining it as an abstract method
# here guarantees that any new adapter that forgets to implement it will raise
# a clear error at instantiation time rather than a confusing AttributeError
# deep inside the scanning loop.
class BaseTargetAdapter(ABC):
    """
    Abstract base class that every target adapter must inherit from.
    Enforces a single-method contract: send_prompt(user_prompt) -> str.
    """

    @abstractmethod
    def send_prompt(self, user_prompt: str) -> str:
        """
        Send a prompt to the target chatbot and return its response.
        Must be overridden by every concrete adapter subclass.
        """
        pass

# ==========================================================
# The Selenium UI Web Target
# ==========================================================
# This adapter uses Selenium to physically type multi-turn prompts into a target chatbot's web interface, allowing for real-time adaptive attacks that 
# can manipulate the chatbot's context or extract information over multiple turns.
class SeleniumTargetAdapter(BaseTargetAdapter):
    """
    Adapter that uses Selenium to physically type multi-turn prompts 
    into a target chatbot's web interface (Mechanism 3 & 4).
    """
    def __init__(self, target_url: str, input_selector: str, response_selector: str):
        """
        :param target_url: The URL of the chatbot (e.g., "http://localhost:5000/chat")
        :param input_selector: CSS Selector for the typing box (e.g., "textarea#prompt-input")
        :param response_selector: CSS Selector for the bot's reply bubbles (e.g., ".bot-message")
        """
        self.target_url = target_url
        self.input_selector = input_selector
        self.response_selector = response_selector
        
        # Initialize the Chrome browser using the webdriver manager to handle driver installation and updates automatically.
        options = ChromeOptions()

        # This automatically downloads and uses the correct Chrome driver!
        service = Service(ChromeDriverManager().install())

        # options.add_argument('--headless') #Note this possible option Uncomment to run invisibly without opening a GUI window
        self.driver = ChromeDriver(service=service, options=options)
        self.driver.get(self.target_url)
        
        # Wait for page to load
        time.sleep(2) 

    # The send_prompt method simulates a user typing a message into the chatbot's web interface and then scrapes the newest response.
    # It includes error handling to ensure the scanner remains robust even if the web interface changes or fails to load.
    def send_prompt(self, user_prompt: str) -> str:
        """Simulates a user typing a message and scraping the newest response."""
        try:
            # Selenium's WebDriverWait is used to ensure that the elements are present before we interact with them,
            # which makes the scanner more robust against varying load times and minor UI changes.
            wait = WebDriverWait(self.driver, 20)
            
            # 1. Count existing messages BEFORE sending the new prompt
            initial_responses = self.driver.find_elements(By.CSS_SELECTOR, self.response_selector)
            initial_count = len(initial_responses)
            
            # 2. Find the input box and type the payload
            input_box = wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, self.input_selector)))
            input_box.clear()
            input_box.send_keys(user_prompt)
            input_box.send_keys(Keys.RETURN) # Hit Enter
            
            # 3. Wait DYNAMICALLY for a new response bubble to appear
            # We use a custom lambda function that waits until the number of bubbles increases
            wait.until(
                lambda driver: len(driver.find_elements(By.CSS_SELECTOR, self.response_selector)) > initial_count,
                message="Timeout waiting for new chatbot response bubble to appear."
            )
            
            # 4. Handle "Streaming" Text (Wait for the LLM to finish typing)
            # We watch the newest bubble. If the text doesn't change for 1.5 seconds, we assume it's done.
            newest_bubble = self.driver.find_elements(By.CSS_SELECTOR, self.response_selector)[-1]
            
            last_text = ""
            unchanged_cycles = 0
            
            while unchanged_cycles < 3:  # 3 cycles of 0.5s = 1.5 seconds of silence
                current_text = newest_bubble.text
                if current_text == last_text and current_text != "":
                    unchanged_cycles += 1
                else:
                    unchanged_cycles = 0  # Reset if the bot is still typing
                    last_text = current_text
                time.sleep(0.5) # Short micro-sleep to prevent freezing the CPU
            
            # 5. Return the fully generated text
            return last_text
                
        except Exception as e:
            logger.error(f"Selenium interaction failed: {e}")
            return "Error: Web UI interaction failed."

    # The close method ensures that the browser is properly closed after the scan is complete, preventing resource leaks. 
    # It includes error handling to catch any issues that may arise when quitting the WebDriver.
    def close(self):
        """Closes the browser when the scan is done."""
        try:
            self.driver.quit()
        except Exception as e:
            logger.error(f"Error closing Selenium WebDriver: {e}")

# ==========================================
# 1. Generic API Target
# ==========================================
# This adapter allows users to scan their own chatbots via API endpoints.
# It is designed to be flexible and can adapt to various API structures by allowing users to specify their endpoint URL, authentication headers, and payload format.
class GenericAPITarget():
    """
    Generic HTTP POST adapter for any chatbot that exposes a REST API.
    Sends { "message": payload } and reads the reply from a configurable
    response field in the returned JSON.

    Constructor parameters
    ----------------------
    endpoint_url   : full URL to POST to, e.g. https://my-bot.com/api/chat
    message_field  : the JSON key to use for the outgoing message (default: "message")
    response_field : the JSON key to read the reply from (default: "response")
                     supports dot-notation for nested fields, e.g. "data.reply"
    api_key        : optional Bearer token sent in the Authorization header
    extra_headers  : optional dict of additional headers
    """
    
    def __init__(self, endpoint_url: str, message_field: str = "message", response_field: str  = "response", api_key: Optional[str]  = None, extra_headers: Optional[dict] = None):
        self.endpoint_url  = endpoint_url
        self.message_field = message_field
        self.response_field = response_field

        self.headers = {"Content-Type": "application/json"}
        if api_key:
            self.headers["Authorization"] = f"Bearer {api_key}"
        if extra_headers:
            self.headers.update(extra_headers)

    def send_prompt(self, payload: str) -> str:
        """POST the payload and return the chatbot's reply as a plain string."""
        import httpx

        try:
            res = httpx.post(
                self.endpoint_url,
                json={self.message_field: payload},
                headers=self.headers,
                timeout=30.0
            )
            res.raise_for_status()
            data = res.json()

            # Support dot-notation for nested response fields
            # e.g. response_field="data.reply" → data["data"]["reply"]
            value = data
            for key in self.response_field.split("."):
                if isinstance(value, dict):
                    value = value.get(key)
                else:
                    value = None
                    break

            if value is None:
                # Field not found — return the entire JSON as a string so the
                # judge still has something to evaluate rather than a silent error
                return str(data)

            return str(value)

        except httpx.HTTPStatusError as e:
            logger.error(f"GenericAPITarget HTTP error: {e.response.status_code} — {e}")
            return f"[SCANNER_ERROR] HTTP {e.response.status_code}: {e}"
        except httpx.RequestError as e:
            logger.error(f"GenericAPITarget connection error: {e}")
            return f"[SCANNER_ERROR] Connection failed: {e}"
        except Exception as e:
            logger.error(f"GenericAPITarget unexpected error: {e}")
            return f"[SCANNER_ERROR] Unexpected error: {e}"

    def close(self):
        pass  # no persistent connection to close for HTTP requests

# ==========================================
# 2. The DeepSeek Demonstration Target
# ==========================================
class DeepSeekDemoTarget(BaseTargetAdapter):
    """Specifically designed to interact with the DeepSeek API as a proof-of-concept victim."""
    
    # The constructor initializes the API key and endpoint URL, and allows for a customizable system prompt to set the tone of the chatbot's responses.
    def __init__(self, system_prompt: str = "You are a helpful assistant."):
        self.api_key = getattr(Config, 'DEEPSEEK_API_KEY', None)
        self.demo_mode = getattr(Config, 'DEMO_MODE', True)
        self.url = "https://api.deepseek.com/chat/completions"
        self.system_prompt = system_prompt

    # The send_prompt method sends the user's prompt to the DeepSeek API and returns the chatbot's response.
    # It also includes error handling to ensure the scanner remains robust even if the DeepSeek API is down.
    def send_prompt(self, user_prompt: str) -> str:
        # If the tool is in demo mode, it simulates a response instead.
        if self.demo_mode:
            return "DEMO MODE: I am a simulated vulnerable chatbot."
            
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": "deepseek-chat",
            "messages": [
                {"role": "system", "content": self.system_prompt},
                {"role": "user", "content": user_prompt}
            ]
        }

        # Error handling to ensure the scanner doesn't crash if the DeepSeek API is down
        try:
            with httpx.Client() as client:
                response = client.post(self.url, headers=headers, json=payload, timeout=30.0)
                response.raise_for_status()
                return response.json()['choices'][0]['message']['content']
        except httpx.HTTPError:
            logger.error("Network error with DeepSeek demo target.")
            return "Error: Demo target unreachable."

# ==========================================================
# 3. Specialized Adapter for the Damn Vulnerable LLM Agent
# ==========================================================
# This is a specialized adapter for the Damn Vulnerable LLM Agent, which is a Streamlit-based vulnerable chatbot running on localhost:8501.
# It uses Selenium to interact with the Streamlit chat interface, allowing us to test real-time prompt injections and other attacks against this intentionally vulnerable target.
class DVLASeleniumTarget():
    """
    Selenium adapter for the Damn Vulnerable LLM Agent.
    Requires the DVLA Docker container to be running on localhost:8501.

    Headless mode is deliberately OFF so the user can watch interactions
    live in the browser window during a DVLA scan (Question 2).
    """
    
    # DVLA's UI has some fixed "loading states" that appear while the agent is thinking. We can use these to help determine when a response is complete.
    _DVLA_LOADING_STATES = {
        "thinking...",
        "complete!",
        "complete",
        "",
    }

    def __init__(self, base_url="http://localhost:8501", response_selector: str = '[data-testid="stChatMessage"]'):
        self.base_url = base_url
        options = ChromeOptions()
        options.add_argument("--no-sandbox")        # required inside some Docker setups
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--window-size=1200,800") # ensure enough space for Streamlit UI elements
        self.driver = ChromeDriver(options=options)
        self.driver.get(base_url)
        self.response_selector = response_selector
        time.sleep(5)
    
    def _get_stable_response(self, driver, timeout: int = 60) -> str:
        """
        Polls the response element until it contains a stable, non-transient value.
        Waits up to `timeout` seconds total; returns the stable text or a
        [SCANNER_ERROR] string if it never settles.
        """
        deadline = time.time() + timeout
        last_text = ""
        stable_count = 0          # how many consecutive polls saw the same non-loading text
        required_stable = 3       # must see same text this many times in a row to accept it
        poll_interval  = 1.5      # seconds between polls — increase if still capturing mid-states

        while time.time() < deadline:
            try:
                elements = self.driver.find_elements(By.CSS_SELECTOR, self.response_selector)
                if not elements:
                    time.sleep(poll_interval)
                    continue

                # Take the last message bubble — that's the agent's most recent reply
                current_text = elements[-1].text.strip()

                # Skip if it's a known transient state
                if current_text.lower() in DVLASeleniumTarget._DVLA_LOADING_STATES:
                    stable_count = 0
                    last_text = current_text
                    time.sleep(poll_interval)
                    continue

                # Also skip if it starts with common partial-render prefixes
                if current_text.lower().startswith("thinking"):
                    stable_count = 0
                    last_text = current_text
                    time.sleep(poll_interval)
                    continue

                # Text is non-transient — check for stability
                if current_text == last_text:
                    stable_count += 1
                    if stable_count >= required_stable:
                        return current_text   # settled — safe to capture
                else:
                    stable_count = 1          # text changed; reset stability counter
                    last_text = current_text

                time.sleep(poll_interval)

            except Exception as e:
                return f"[SCANNER_ERROR] Response polling failed: {e}"

        return f"[SCANNER_ERROR] Response did not stabilise within {timeout}s"

    def send_prompt(self, payload: str, fresh_session: bool = True, timeout: int = 15) -> str:
        """
        Types the payload into the DVLA chatbot and waits for a fully-settled,
        non-transient assistant response before returning.

        Parameters
        ----------
        payload       : the text to send to the chatbot
        fresh_session : when True (default) the page is refreshed first,
                        giving every independent probe a clean slate.
                        Set to False for turns 2-N of a multi-turn attack so
                        the full conversation history is preserved in Streamlit —
                        allowing the attack to build naturally over several turns.
        timeout       : total seconds to wait for a stable response.
                        Default 15 s keeps the overall scan from running too long.
                        Raise this per-call if the DVLA agent is known to be slow.
        """
        try:
            # ── Session management ───────────────────────────────────────────────
            # Single-turn probes: always start fresh so earlier probes don't
            # pollute the context.
            # Multi-turn continuation: skip the refresh so the chatbot still
            # "remembers" what was said in earlier turns.
            if fresh_session:
                self.driver.refresh()
                # 5 s gives Streamlit enough time to reconnect its WebSocket and
                # render the input widget. The 30-second EC.element_to_be_clickable
                # wait below provides a hard safety net for slow cold-starts.
                time.sleep(5)

            # Wait up to 30 s for the textarea — this is a page-readiness check,
            # kept deliberately generous and independent of the response `timeout`
            # so a slow Streamlit cold-start doesn't cascade into a SCANNER_ERROR.
            # element_to_be_clickable ensures it is both present and interactable.
            wait = WebDriverWait(self.driver, 30)

            input_area = wait.until(
                EC.element_to_be_clickable(
                    (By.CSS_SELECTOR, '[data-testid="stChatInput"] textarea')
                )
            )

            input_area.click()
            input_area.send_keys(payload)

            # Count messages that already exist so we can identify new ones later
            pre_send_count = len(
                self.driver.find_elements(By.CSS_SELECTOR, '[data-testid="stChatMessage"]')
            )

            input_area.send_keys(Keys.RETURN)

            # ── Spinner lifecycle ────────────────────────────────────────────────
            # Wait for the Streamlit status spinner to appear (agent started work)…
            try:
                WebDriverWait(self.driver, 8).until(
                    EC.presence_of_element_located(
                        (By.CSS_SELECTOR, '[data-testid="stStatusWidget"]')
                    )
                )
            except Exception:
                pass   # spinner sometimes skipped for very fast responses

            # …then wait for it to disappear (agent finished processing).
            # Capped at the caller's timeout so we don't wait longer than the
            # total budget allows.
            try:
                WebDriverWait(self.driver, timeout).until(
                    EC.invisibility_of_element_located(
                        (By.CSS_SELECTOR, '[data-testid="stStatusWidget"]')
                    )
                )
            except Exception:
                logger.warning("DVLA spinner wait timed out — proceeding to polling")

            # ── Wait for at least user bubble + one assistant bubble ─────────────
            # Waiting for strictly more than pre_send_count was too early —
            # it could fire as soon as the user's own bubble appeared, before
            # the agent had started writing its reply.
            try:
                WebDriverWait(self.driver, min(timeout, 15)).until(
                    lambda d: len(d.find_elements(
                        By.CSS_SELECTOR, '[data-testid="stChatMessage"]'
                    )) > pre_send_count + 1
                )
            except Exception:
                logger.warning("DVLA: fewer than 2 new message bubbles appeared — proceeding")

            # ── Stability loop ───────────────────────────────────────────────────
            # Even after the spinner clears, the last message bubble often still
            # holds a transient value ("Thinking…", a tool-call result, etc.).
            # We poll the LAST assistant bubble until its text is:
            #   (a) not a known transient state, AND
            #   (b) identical for `required` consecutive polls (≈ stable).
            # `timeout` is 20 s for single-turn probes and 30 s for multi-turn
            # continuation turns (passed in by send_prompt_continue).
            deadline      = time.time() + timeout
            last_text     = ""
            stable_count  = 0
            required      = 3          # 3 × 1.5 s = 4.5 s of confirmed stability
            poll_interval = 1.5
            final_text    = None

            while time.time() < deadline:
                all_msgs  = self.driver.find_elements(
                    By.CSS_SELECTOR, '[data-testid="stChatMessage"]'
                )
                new_msgs  = all_msgs[pre_send_count:]   # only messages from this turn
                asst_msgs = new_msgs[1:]                # skip the user's own bubble

                if not asst_msgs:
                    time.sleep(poll_interval)
                    continue

                # Always check the LAST bubble — it is the most recent reply
                current = asst_msgs[-1].text.strip()

                # Skip any known transient / tool-call state
                transient = (
                    current.lower() in DVLASeleniumTarget._DVLA_LOADING_STATES
                    or current.lower().startswith("thinking")
                    or current.lower().startswith("check\n")
                    or current.lower().startswith("getcurrentuser")
                    or current.lower().startswith("getusertransactions")
                )
                if transient:
                    stable_count = 0
                    last_text    = current
                    time.sleep(poll_interval)
                    continue

                # Non-transient text — measure stability
                if current == last_text and current:
                    stable_count += 1
                    if stable_count >= required:
                        final_text = current
                        break
                else:
                    stable_count = 1 if current else 0
                    last_text    = current

                time.sleep(poll_interval)

            # If the loop timed out without confirming stability, use the last
            # non-empty, non-transient text we observed rather than giving up.
            if final_text is None:
                if last_text and last_text.lower() not in DVLASeleniumTarget._DVLA_LOADING_STATES:
                    logger.warning("DVLA response timed out — using last captured text")
                    final_text = last_text
                else:
                    return "[SCANNER_ERROR] DVLA response did not stabilise within timeout"

            # ── Artifact cleanup ─────────────────────────────────────────────────
            artifact_patterns = [
                r'^check\s*\n',
                r'^Complete!\s*\n',
                r'^GetCurrentUser:.*\n',
                r'^GetUserTransactions:.*\n',
                r'^Thinking\.\.\.\s*\n',
            ]
            cleaned = final_text
            for pattern in artifact_patterns:
                cleaned = re.sub(pattern, '', cleaned, flags=re.IGNORECASE | re.MULTILINE)
            cleaned = cleaned.strip()

            if not cleaned:
                return "[SCANNER_ERROR] DVLA agent only produced tool artifacts, no final answer"

            # ── Static non-relevant response detection ───────────────────────────
            # The DVLA LangChain agent sometimes responds to attack payloads by
            # simply running its normal tool pipeline (GetCurrentUser →
            # GetUserTransactions) and returning a transaction table.  This is the
            # agent treating the probe as a routine data-retrieval request rather
            # than reacting to the attack — the response is real but carries no
            # vulnerability signal worth sending to the LLM Judge.
            # Detect this pattern and return a fixed sentinel so the engine logs it
            # as a non-scoreable "static non-relevant" result rather than wasting an
            # OpenAI call on data rows.
            static_indicators = [
                "transaction id",           # table header present
                "here are your recent transactions",
                "your recent transactions",
            ]
            cleaned_lower = cleaned.lower()
            if any(ind in cleaned_lower for ind in static_indicators):
                logger.info("DVLA returned a static transaction-table response — skipping LLM judge.")
                return "DVLA returned static non-relevant response"

            # ── Error detection ──────────────────────────────────────────────────
            if 'getcurrentuser' in cleaned.lower() and len(cleaned) < 80:
                return "[SCANNER_ERROR] DVLA agent stuck in tool loop without final answer"

            error_signals = [
                "llm encountered an error", "notfounderror", "openaiexception",
                "langchainerror", "could not parse"
            ]
            if any(sig in cleaned.lower() for sig in error_signals):
                logger.warning(f"DVLA LLM error: {cleaned[:80]}")
                return f"[SCANNER_ERROR] DVLA LLM error: {cleaned[:120]}"

            return cleaned

        except Exception as e:
            logger.error(f"DVLA Selenium interaction failed: {e}")
            return f"[SCANNER_ERROR] Selenium error: {e}"

    def send_prompt_continue(self, payload: str) -> str:
        """
        Sends a follow-up prompt within the SAME Streamlit session (no page
        refresh).  Used for turns 2-N of a multi-turn attack so the full
        conversation history is preserved and the attack can build naturally
        over several turns — mimicking a real user's ongoing conversation.

        Uses a 30-second stability timeout (vs. the 20-second default for
        single-turn probes) because multi-turn sessions accumulate context that
        makes the LangChain agent's reasoning slightly longer.
        """
        return self.send_prompt(payload, fresh_session=False, timeout=15)

    def reset(self):
        self.driver.refresh()
        time.sleep(5)

    def close(self):
        try:
            self.driver.quit()
        except Exception as e:
            logger.error(f"Error closing DVLA browser: {e}")