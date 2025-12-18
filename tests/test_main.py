from unittest.mock import MagicMock, patch

import pytest

from src.main import main


class TestMain:
    """Tests for main function"""

    @patch('src.main.Traceroute')
    @patch('src.main.parse_args')
    def test_main_successful_execution(self, mock_parse_args: MagicMock, mock_traceroute_class: MagicMock) -> None:
        """Test main function with successful execution"""
        # Mock the parsed arguments
        mock_args = type('MockArgs', (), {'p': 53, 'ip': '8.8.8.8', 't': 2, 'n': 3, 'mt': 30, 'i': 0, 's': 40})()
        mock_parse_args.return_value = mock_args

        # Mock the traceroute instance
        mock_traceroute_instance = mock_traceroute_class.return_value

        # Call main
        main()

        # Verify parse_args was called
        mock_parse_args.assert_called_once()

        # Verify Traceroute was created with correct arguments
        mock_traceroute_class.assert_called_once_with(
            port=53, ip='8.8.8.8', timeout=2, number_of_requests=3, max_ttl=30, interval=0, size_of_packet=40
        )

        # Verify methods were called
        mock_traceroute_instance.analyze_ip.assert_called_once()
        mock_traceroute_instance.run.assert_called_once()
        mock_traceroute_instance.view_routers.assert_called_once()

    @patch('src.main.Traceroute')
    @patch('src.main.parse_args')
    def test_main_with_custom_arguments(self, mock_parse_args: MagicMock, mock_traceroute_class: MagicMock) -> None:
        """Test main function with custom command line arguments"""
        # Mock custom arguments
        mock_args = type('MockArgs', (), {'p': 80, 'ip': '192.168.1.1', 't': 5, 'n': 2, 'mt': 25, 'i': 1, 's': 60})()
        mock_parse_args.return_value = mock_args

        mock_traceroute_instance = mock_traceroute_class.return_value

        main()

        # Verify Traceroute was created with custom arguments
        mock_traceroute_class.assert_called_once_with(
            port=80, ip='192.168.1.1', timeout=5, number_of_requests=2, max_ttl=25, interval=1, size_of_packet=60
        )

        # Verify execution flow
        mock_traceroute_instance.analyze_ip.assert_called_once()
        mock_traceroute_instance.run.assert_called_once()
        mock_traceroute_instance.view_routers.assert_called_once()

    @patch('src.main.Traceroute')
    @patch('src.main.parse_args')
    def test_main_analyze_ip_failure(self, mock_parse_args: MagicMock, mock_traceroute_class: MagicMock) -> None:
        """Test main function when analyze_ip raises an exception"""
        mock_args = type('MockArgs', (), {'p': 53, 'ip': 'invalid.ip', 't': 2, 'n': 3, 'mt': 30, 'i': 0, 's': 40})()
        mock_parse_args.return_value = mock_args

        mock_traceroute_instance = mock_traceroute_class.return_value
        mock_traceroute_instance.analyze_ip.side_effect = ValueError("Invalid IP address")

        # Should propagate the exception
        with pytest.raises(ValueError, match="Invalid IP address"):
            main()

        # Verify analyze_ip was called but run and view_routers were not
        mock_traceroute_instance.analyze_ip.assert_called_once()
        mock_traceroute_instance.run.assert_not_called()

    @patch('src.main.Traceroute')
    @patch('src.main.parse_args')
    def test_main_run_failure(self, mock_parse_args: MagicMock, mock_traceroute_class: MagicMock) -> None:
        """Test main function when run method raises an exception"""
        mock_args = type('MockArgs', (), {'p': 53, 'ip': '8.8.8.8', 't': 2, 'n': 3, 'mt': 30, 'i': 0, 's': 40})()
        mock_parse_args.return_value = mock_args

        mock_traceroute_instance = mock_traceroute_class.return_value
        mock_traceroute_instance.run.side_effect = RuntimeError("Network error")

        # Should propagate the exception
        with pytest.raises(RuntimeError, match="Network error"):
            main()

        # Verify all methods up to the failure were called
        mock_traceroute_instance.analyze_ip.assert_called_once()
        mock_traceroute_instance.run.assert_called_once()
        mock_traceroute_instance.view_routers.assert_not_called()
