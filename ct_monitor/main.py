import argparse
import os
import sys
from datetime import datetime
from dotenv import load_dotenv

from .constants import __version__
from .config import DEFAULT_CONFIG, load_config_file, create_sample_config
from .monitor import CTMonitor

def main():
    load_dotenv()
    parser = argparse.ArgumentParser(
        description="Certificate Transparency Log Monitor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --once                           # Run once and exit
  %(prog)s --continuous                     # Run continuously
  %(prog)s --output-format csv --output-file domains.csv
  %(prog)s --config config.json            # Use custom config
  %(prog)s --create-config                 # Create sample config
  %(prog)s --ai-mode --ai-model gemini-1.5-flash-latest # Run with AI phishing detection
        """
    )
    
    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')
    parser.add_argument('--config', help='Configuration file path')
    parser.add_argument('--create-config', metavar='FILE', help='Create sample configuration file')
    
    # Execution modes
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument('--once', action='store_true', help='Run once and exit')
    mode_group.add_argument('--continuous', action='store_true', default=True, help='Run continuously (default)')
    mode_group.add_argument('--ai-mode', action='store_true', help='Run once and analyze domains with AI for phishing')
    
    # Monitoring options
    parser.add_argument('--skip-catchup', action='store_true',
                       help='Start monitoring from current log size, ignoring historical entries (useful for AI mode)')
    parser.add_argument('--keywords', help='Comma-separated list of keywords to monitor (overrides config)')

    # Output options
    parser.add_argument('--output-format', choices=['json', 'csv', 'txt'],
                       help='Output format (default: json)')
    parser.add_argument('--output-file', help='Output file path')
    parser.add_argument('--state-file', help='State file path')
    
    # Monitoring options
    parser.add_argument('--poll-interval', type=int, help='Polling interval in seconds')
    parser.add_argument('--max-workers', type=int, help='Maximum worker threads')
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                       help='Logging level')

    # AI options
    parser.add_argument('--ai-provider', choices=['google', 'openrouter'], default='google',
                       help='AI provider to use (default: google)')
    parser.add_argument('--ai-model', help='The specific AI model to use')
    parser.add_argument('--max-domains-for-ai', type=int, help='Max domains to send to AI for analysis')
    
    args = parser.parse_args()
    
    # Handle config creation
    if args.create_config:
        create_sample_config(args.create_config)
        return
    
    # Load configuration
    config = DEFAULT_CONFIG.copy()
    
    if args.config:
        file_config = load_config_file(args.config)
        config.update(file_config)
    
    # Override with command line arguments
    if args.output_format:
        config['output_format'] = args.output_format
    if args.output_file:
        config['output_file'] = args.output_file
    if args.state_file:
        config['state_file'] = args.state_file
    if args.poll_interval:
        config['poll_interval_seconds'] = args.poll_interval
    if args.max_workers:
        config['max_workers'] = args.max_workers
    if args.log_level:
        config['log_level'] = args.log_level
        
    if args.ai_mode:
        config['ai_mode'] = True
    if args.ai_provider:
        config['ai_provider'] = args.ai_provider
    if args.ai_model:
        config['ai_model'] = args.ai_model
    if args.max_domains_for_ai:
        config['max_domains_for_ai'] = args.max_domains_for_ai
    
    if args.skip_catchup:
        config['skip_catchup'] = True

    if args.keywords:
        keywords = [k.strip() for k in args.keywords.split(',') if k.strip()]
        config['monitored_keywords'] = keywords

    # Create a unique output directory for this run
    run_mode = "continuous"
    if args.once:
        run_mode = "once"
    elif args.ai_mode:
        run_mode = "ai_mode"
    
    timestamp_str = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    output_dir_name = f"ct_run_{timestamp_str}_{run_mode}"
    
    # Create the directory if it doesn't exist
    try:
        os.makedirs(output_dir_name, exist_ok=True)
        config['output_dir'] = output_dir_name
        print(f"Output will be saved to: {output_dir_name}")
    except OSError as e:
        print(f"Error creating output directory: {e}")
        return

    # Create monitor and run
    monitor = CTMonitor(config)
    
    if args.once or config.get('ai_mode'):
        domain_count = monitor.run_once()
        if not config.get('ai_mode'):
            print(f"Found {domain_count} new domains")
    else:
        monitor.run_continuous()

if __name__ == "__main__":
    main()