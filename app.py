import streamlit as st
from threat_analysis_agent import ThreatAnalysisAgent

def main():
    st.title("Cybersecurity Threat Analysis")

    st.write("Enter a threat report below to analyze:")

    report_text = st.text_area("Threat Report", height=200)

    if st.button("Analyze"):
        if report_text.strip() == "":
            st.warning("Please enter a threat report to analyze.")
        else:
            agent = ThreatAnalysisAgent()
            result = agent.analyze_threat_report(report_text)
            st.subheader("Analysis Result")
            st.write(result)

if __name__ == "__main__":
    main()
