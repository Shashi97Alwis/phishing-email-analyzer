import streamlit as st
import pandas as pd
import sqlite3
import os
import subprocess
import sys
import json
import base64
import plotly.express as px  # <-- NEW IMPORT for charts

# Page Configuration
st.set_page_config(
    page_title="Phishing Email Analyzer",
    page_icon="📧",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Database Connection & Data Loading
DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'phishing_analysis.db')


def get_db_connection():
    """Establishes a connection to the SQLite database."""
    try:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn
    except sqlite3.Error as e:
        st.error(f"Database connection error: {e}")
        return None


def setup_database(conn):
    """Creates the necessary tables if they don't already exist."""
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS emails (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    subject TEXT, sender TEXT, risk_score INTEGER,
                    priority TEXT, analysis_timestamp TEXT,
                    risk_reasons TEXT
                )
            ''')
            # --- CORRECTED SCHEMA: Added scan_id column ---
            cursor.execute('''
                            CREATE TABLE IF NOT EXISTS iocs (
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                email_id INTEGER, ioc_type TEXT, ioc_value TEXT,
                                verdict TEXT, source TEXT,
                                scan_id TEXT,
                                FOREIGN KEY(email_id) REFERENCES emails(id) ON DELETE CASCADE
                            )
            ''')
            conn.commit()
        except sqlite3.Error as e:
            st.error(f"Error setting up database tables: {e}")


def load_email_data(conn):
    """Loads the main email summary data."""
    if conn:
        try:
            query = "SELECT id, subject, sender, risk_score, priority, analysis_timestamp FROM emails ORDER BY risk_score DESC"
            return pd.read_sql_query(query, conn)
        except pd.io.sql.DatabaseError:
            return pd.DataFrame()
        except Exception as e:
            st.error(f"Error loading email data: {e}")
    return pd.DataFrame()


def load_single_email_details(conn, email_id):
    """Loads the full details for a single selected email."""
    if conn:
        try:
            query = "SELECT * FROM emails WHERE id = ?"
            return pd.read_sql_query(query, conn, params=(email_id,)).iloc[0]
        except Exception:
            return None
    return None


def load_iocs_for_email(conn, email_id):
    """Loads all IOCs associated with a specific email ID with better error handling."""
    if conn:
        try:
            query = "SELECT ioc_type, ioc_value, verdict, source, scan_id FROM iocs WHERE email_id = ?"
            return pd.read_sql_query(query, conn, params=(email_id,))
        except Exception as e:
            # --- IMPROVED ERROR HANDLING ---
            # Now, it will show you the actual database error instead of hiding it.
            st.error(f"Error loading IOCs from database: {e}")
            return pd.DataFrame()
    return pd.DataFrame()

# --- NEW: Function for IOC Search ---
def search_for_ioc(conn, search_term):
    """Searches for emails containing a specific IOC value."""
    if conn and search_term:
        try:
            # Use a JOIN query to find emails linked to the IOC
            query = """
                SELECT e.id, e.subject, e.sender, e.risk_score, e.priority, e.analysis_timestamp
                FROM emails e
                JOIN iocs i ON e.id = i.email_id
                WHERE i.ioc_value LIKE ?
                GROUP BY e.id
                ORDER BY e.risk_score DESC
            """
            # Use '%' for a wildcard search to find domains within URLs, etc.
            param = f"%{search_term}%"
            return pd.read_sql_query(query, conn, params=(param,))
        except Exception as e:
            st.error(f"Error during IOC search: {e}")
    return pd.DataFrame()

# Styling Functions
def style_priority_row(row):
    """Applies a background color to a row based on its priority level."""
    priority_colors = {
        "Very High": '#ffcccc', "High": '#ffe0b3', "Medium": '#ffffcc',
        "Low": '#cce6ff', "Very Low": '#ccffcc', "Informational": '#f0f0f0'
    }
    color = priority_colors.get(row.priority, "white")
    return [f'background-color: {color}' for _ in row]


def get_priority_styles():
    """
    Generates custom CSS to color the multiselect filter tags.
    The order of rules is important to handle overlapping selectors.
    """
    return """
        <style>
            .stMultiSelect [data-baseweb="tag"] {
                border-radius: 0.25rem;
                padding: 0.1rem 0.6rem;
                color: black;
            }
            /* General 'High' rule comes FIRST */
            .stMultiSelect [data-baseweb="tag"][aria-label*="High"] {
                background-color: #ff9933 !important;
                color: white !important;
            }
            /* More specific 'Very High' rule comes AFTER to override */
            .stMultiSelect [data-baseweb="tag"][aria-label*="Very High"] {
                background-color: #ff4b4b !important;
                color: white !important;
            }
            .stMultiSelect [data-baseweb="tag"][aria-label*="Medium"] {
                background-color: #ffff99 !important;
            }
            .stMultiSelect [data-baseweb="tag"][aria-label*="Low"] {
                background-color: #add8e6 !important;
            }
            .stMultiSelect [data-baseweb="tag"][aria-label*="Very Low"] {
                background-color: #90ee90 !important;
            }
            .stMultiSelect [data-baseweb="tag"][aria-label*="Informational"] {
                background-color: #d3d3d3 !important;
            }
            .stMultiSelect [data-baseweb="tag"] span[role="button"] {
                color: inherit !important;
            }
        </style>
    """

# --- NEW: Helper function for CSV conversion ---
@st.cache_data
def convert_df_to_csv(df):
    """Converts a DataFrame to a CSV string for downloading."""
    return df.to_csv(index=False).encode('utf-8')

# Main Dashboard UI
st.title("📧 Phishing Email Analyzer Dashboard")
st.markdown("An automated tool to detect, analyze, and prioritize potential phishing threats from an inbox.")

# Inject the custom CSS
st.markdown(get_priority_styles(), unsafe_allow_html=True)

# Sidebar
st.sidebar.header("Actions")
if st.sidebar.button("Run New Analysis", type="primary"):
    st.sidebar.info("Starting new analysis... This may take a moment.")
    try:
        analyzer_path = os.path.join(os.path.dirname(__file__), 'analyzer.py')
        with st.spinner('The backend is fetching emails and calling APIs... Please wait.'):
            process = subprocess.run(
                [sys.executable, analyzer_path],
                capture_output=True, text=True, check=True
            )
            st.sidebar.success("Analysis complete!")
            with st.sidebar.expander("Show Analysis Logs"):
                st.code(process.stdout)
            if process.stderr:
                st.sidebar.error("Errors occurred during analysis:")
                st.sidebar.code(process.stderr)
    except subprocess.CalledProcessError as e:
        st.sidebar.error("Failed to run analyzer script.")
        with st.sidebar.expander("Show Error Details"):
            st.code(e.stdout)
            st.code(e.stderr)
    except FileNotFoundError:
        st.sidebar.error(f"Could not find analyzer.py at {analyzer_path}")

# --- NEW: Threat Hunting Search Bar in Sidebar ---
st.sidebar.header("Threat Hunting")
search_term = st.sidebar.text_input("Search for an IOC (IP, URL, Hash):")

# Main Content
conn = get_db_connection()
setup_database(conn)

# --- UPDATED: Main logic now depends on whether a search is active ---
if search_term:
    st.subheader(f"🔍 Search Results for: `{search_term}`")
    search_results_df = search_for_ioc(conn, search_term)

    if not search_results_df.empty:
        st.dataframe(
            search_results_df.style.apply(style_priority_row, axis=1),
            use_container_width=True
        )
    else:
        st.info("No emails found containing that indicator.")
else:
    # This is the default view when not searching
    email_df = load_email_data(conn)

    if email_df.empty:
        st.warning("No analysis data found in the database. Please run a new analysis.")
    else:
        st.subheader("Latest Analysis Summary")
        total_emails = len(email_df)
        priority_counts = email_df['priority'].value_counts()
        col1, col2, col3, col4, col5 = st.columns(5)
        col1.metric("Total Emails Analyzed", total_emails)
        col2.metric("Very High Priority", priority_counts.get("Very High", 0))
        col3.metric("High Priority", priority_counts.get("High", 0))
        col4.metric("Medium Priority", priority_counts.get("Medium", 0))
        col5.metric("Low Priority", priority_counts.get("Low", 0) + priority_counts.get("Very Low", 0))

        st.subheader("Visualizations")
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("##### Priority Distribution")
            priority_data = email_df['priority'].value_counts().reset_index()
            priority_data.columns = ['priority', 'count']
            fig_pie = px.pie(priority_data, names='priority', values='count', color='priority',
                             color_discrete_map={"Very High": '#ff4b4b', "High": '#ff9933', "Medium": '#ffff99',
                                                 "Low": '#add8e6', "Very Low": '#90ee90', "Informational": '#d3d3d3'})
            st.plotly_chart(fig_pie, use_container_width=True)
        with col2:
            st.markdown("##### Top 5 Riskiest Senders")
            risky_senders = email_df.groupby('sender')['risk_score'].mean().sort_values(ascending=False).head(5)
            st.bar_chart(risky_senders)

        st.subheader("Analyzed Emails")
        priority_order = ["Very High", "High", "Medium", "Low", "Very Low", "Informational"]
        available_priorities = [p for p in priority_order if p in email_df['priority'].unique()]
        priority_filter = st.multiselect("Filter by Priority:", options=available_priorities,
                                         default=available_priorities)
        filtered_df = email_df[email_df['priority'].isin(priority_filter)]
        st.dataframe(filtered_df.style.apply(style_priority_row, axis=1), use_container_width=True)

        csv_data = convert_df_to_csv(filtered_df)
        st.download_button(label="📥 Download Current View as CSV", data=csv_data,
                           file_name='phishing_analysis_report.csv', mime='text/csv')

        # Detailed Analysis View
        st.subheader("Detailed Analysis")
        if not filtered_df.empty:
            email_options = [f"ID {row.id}: {row.subject}" for index, row in filtered_df.iterrows()]
            selected_email_str = st.selectbox("Select an email to view its detailed report:", options=email_options)

            if selected_email_str:
                selected_id = int(selected_email_str.split(':')[0].replace('ID', '').strip())
                email_details = load_single_email_details(conn, selected_id)
                ioc_details_df = load_iocs_for_email(conn, selected_id)

                if email_details is not None:
                    st.markdown("---")
                    st.markdown(f"#### Report for Email ID: {email_details['id']}")
                    c1, c2, c3 = st.columns(3)
                    c1.metric("Final Risk Score", email_details['risk_score'])
                    c2.metric("Priority", email_details['priority'])
                    c3.metric("Analyzed On", email_details['analysis_timestamp'])
                    st.text_area("Subject", email_details['subject'], height=50, disabled=True)
                    st.text_input("Sender", email_details['sender'], disabled=True)

                    with st.expander("Score Breakdown"):
                        st.write("This section shows the specific factors that contributed to the email's risk score.")
                        try:
                            reasons_list = json.loads(email_details['risk_reasons'])
                            if reasons_list:
                                reasons_df = pd.DataFrame(reasons_list, columns=['Reason', 'Score'])
                                st.table(reasons_df)
                            else:
                                st.info("No specific risk factors were recorded for this score.")
                        except (json.JSONDecodeError, TypeError):
                            st.warning("Could not parse the reasons for the score.")

                    with st.expander("Detected Indicators of Compromise (IOCs)", expanded=True):
                        st.write("This section lists all IPs, URLs, and file hashes found and their verdicts.")
                        if not ioc_details_df.empty:
                            for ioc_type in ['ip', 'url', 'hash']:
                                iocs = ioc_details_df[ioc_details_df['ioc_type'] == ioc_type]
                                if not iocs.empty:
                                    st.markdown(f"**{ioc_type.upper()}s Found**")
                                    for index, row in iocs.iterrows():
                                        ioc_value = row['ioc_value']
                                        col1, col2, col3 = st.columns([2, 1, 1])
                                        with col1:
                                            st.code(ioc_value, language=None)
                                        with col2:
                                            vt_link = ""
                                            if ioc_type == 'ip':
                                                vt_link = f"https://www.virustotal.com/gui/ip-address/{ioc_value}"
                                            elif ioc_type == 'url':
                                                url_id = base64.urlsafe_b64encode(ioc_value.encode()).decode().strip(
                                                    "=")
                                                vt_link = f"https://www.virustotal.com/gui/url/{url_id}"
                                            elif ioc_type == 'hash':
                                                vt_link = f"https://www.virustotal.com/gui/file/{ioc_value}"
                                            if vt_link: st.markdown(f"[View on VirusTotal]({vt_link})")
                                        with col3:
                                            if ioc_type == 'ip':
                                                abuse_link = f"https://www.abuseipdb.com/check/{ioc_value}"
                                                st.markdown(f"[View on AbuseIPDB]({abuse_link})")
                                            if ioc_type == 'url' and row['scan_id']:
                                                urlscan_link = f"https://urlscan.io/result/{row['scan_id']}"
                                                st.markdown(f"[View on URLScan.io]({urlscan_link})")
                        else:
                            st.info("No IOCs were recorded for this email.")
                else:
                    st.error("Could not retrieve details for the selected email.")

if conn:
    conn.close()
