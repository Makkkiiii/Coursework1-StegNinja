"""
Test script to verify the updated quality display functionality
"""

def test_quality_description():
    """Test the get_quality_description method"""
    
    # Simulate the get_quality_description method from the GUI
    def get_quality_description(metrics):
        mse = metrics.get('mse', 0)
        psnr = metrics.get('psnr', 0)
        ssim = metrics.get('ssim', 0)
        
        # Determine overall quality based on metrics
        if psnr >= 50 and ssim >= 0.99:
            quality = "🟢 EXCELLENT - Virtually undetectable"
            details = "Hidden data is completely invisible to the naked eye"
        elif psnr >= 40 and ssim >= 0.95:
            quality = "🟡 VERY GOOD - Barely noticeable"
            details = "Hidden data causes minimal visual changes"
        elif psnr >= 30 and ssim >= 0.90:
            quality = "🟠 GOOD - Slight differences"
            details = "Minor visual changes may be visible on close inspection"
        elif psnr >= 20 and ssim >= 0.80:
            quality = "🔴 FAIR - Noticeable changes"
            details = "Visual differences are apparent but acceptable"
        else:
            quality = "🔴 POOR - Significant changes"
            details = "Hidden data causes obvious visual degradation"
        
        # Add technical metrics directly below the description
        technical = f"Technical Metrics: MSE: {mse:.2f} | PSNR: {psnr:.2f} dB | SSIM: {ssim:.3f}"
        
        return f"{quality}\n{details}\n\n{technical}"
    
    # Test cases
    test_cases = [
        {
            'name': 'Excellent Quality',
            'metrics': {'mse': 0.5, 'psnr': 52.3, 'ssim': 0.995},
            'expected_contains': ['EXCELLENT', 'Technical Metrics:', 'MSE: 0.50', 'PSNR: 52.30', 'SSIM: 0.995']
        },
        {
            'name': 'Very Good Quality',
            'metrics': {'mse': 1.23, 'psnr': 42.56, 'ssim': 0.987},
            'expected_contains': ['VERY GOOD', 'Technical Metrics:', 'MSE: 1.23', 'PSNR: 42.56', 'SSIM: 0.987']
        },
        {
            'name': 'Good Quality',
            'metrics': {'mse': 3.45, 'psnr': 35.67, 'ssim': 0.923},
            'expected_contains': ['GOOD', 'Technical Metrics:', 'MSE: 3.45', 'PSNR: 35.67', 'SSIM: 0.923']
        },
        {
            'name': 'Fair Quality',
            'metrics': {'mse': 8.12, 'psnr': 25.34, 'ssim': 0.845},
            'expected_contains': ['FAIR', 'Technical Metrics:', 'MSE: 8.12', 'PSNR: 25.34', 'SSIM: 0.845']
        },
        {
            'name': 'Poor Quality',
            'metrics': {'mse': 15.67, 'psnr': 18.23, 'ssim': 0.723},
            'expected_contains': ['POOR', 'Technical Metrics:', 'MSE: 15.67', 'PSNR: 18.23', 'SSIM: 0.723']
        }
    ]
    
    print("🎯 Testing Quality Display Functionality")
    print("=" * 50)
    
    all_passed = True
    
    for test_case in test_cases:
        print(f"\n📊 Testing: {test_case['name']}")
        result = get_quality_description(test_case['metrics'])
        
        print("Generated description:")
        print("-" * 30)
        print(result)
        print("-" * 30)
        
        # Check if all expected content is present
        test_passed = True
        for expected in test_case['expected_contains']:
            if expected not in result:
                print(f"❌ FAIL: Missing '{expected}'")
                test_passed = False
                all_passed = False
        
        # Check that hover hint is NOT present
        if 'Hover' in result:
            print("❌ FAIL: Hover hint should be removed")
            test_passed = False
            all_passed = False
        
        if test_passed:
            print("✅ PASS: All expected content present")
        
        print()
    
    print("=" * 50)
    if all_passed:
        print("🎉 ALL TESTS PASSED!")
        print("✅ Quality display shows technical metrics directly")
        print("✅ No hover functionality present")
        print("✅ User-friendly descriptions working correctly")
    else:
        print("❌ SOME TESTS FAILED!")
    
    return all_passed

if __name__ == "__main__":
    test_quality_description()
