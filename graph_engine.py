import matplotlib.pyplot as plt
import io
import base64
import pandas as pd
import matplotlib.dates as mdates
import matplotlib
matplotlib.use('Agg')

def get_base64_chart(fig):
    img = io.BytesIO()
    # High DPI (120) ensures the text is sharp
    fig.savefig(img, format='png', bbox_inches='tight', facecolor='#1e293b', dpi=120)
    img.seek(0)
    plt.close(fig)
    return base64.b64encode(img.getvalue()).decode('utf-8')

def generate_geo_chart(df):
    clean_df = df[df['CountryCode'].notna()]
    counts = clean_df['CountryCode'].value_counts().head(5)
    fig, ax = plt.subplots(figsize=(6, 4))
    plt.style.use('dark_background')
    colors = ['#ff3131', '#39ff14', '#38bdf8', '#fefe33', '#94a3b8']
    ax.pie(counts, labels=counts.index, autopct='%1.1f%%', colors=colors, startangle=140)
    ax.set_title("Threat Origin Distribution", pad=20)
    return get_base64_chart(fig)

def generate_velocity_chart(df):
    plt.style.use('dark_background')
    fig, ax = plt.subplots(figsize=(12, 5)) 
    
    df['CreatedAt'] = pd.to_datetime(df['CreatedAt'])
    
    # Resample by second
    velocity = df.set_index('CreatedAt').resample('s').size()

    # --- THE ZOOM FIX ---
    # We force the X-axis to only show the range where data actually exists
    start_time = df['CreatedAt'].min()
    end_time = df['CreatedAt'].max()
    ax.set_xlim(start_time, end_time)

    ax.plot(velocity.index, velocity.values, color='#39ff14', linewidth=1.5)
    ax.fill_between(velocity.index, velocity.values, color='#39ff14', alpha=0.1)
    
    # Format to show Hour:Minute:Second
    ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
    
    # Force strictly 6 to 8 labels so they never overlap
    ax.xaxis.set_major_locator(plt.MaxNLocator(8))
    
    plt.xticks(rotation=30, ha='right', fontsize=9, color='#94a3b8')
    plt.yticks(fontsize=9, color='#94a3b8')
    
    ax.set_title("Real-Time Forensic Velocity (Attack Spikes)", color='white', pad=20, fontsize=14)
    ax.set_ylabel("Attempts / Second", color='#94a3b8')
    
    plt.tight_layout()
    return get_base64_chart(fig)


def generate_site_pressure_chart(df):
    site_map = {1: 'Social', 2: 'Bank', 3: 'Shop', 4: 'Edu'}
    df['SiteName'] = df['SiteId'].map(site_map)
    pressure = df['SiteName'].value_counts()
    fig, ax = plt.subplots(figsize=(6, 4))
    plt.style.use('dark_background')
    pressure.plot(kind='barh', color='#ff3131', ax=ax)
    ax.set_title("Endpoint Pressure Level")
    return get_base64_chart(fig)