use crate::system::measure_gflops;
use crate::environment::Environment;

/// 渲染ASCII艺术横幅
pub fn render_ascii_banner(text: &str) -> Vec<String> {
    let height = 7; // ASCII艺术高度
    let mut result = vec![String::new(); height];

    for c in text.chars() {
        match c {
            'N' => {
                result[0].push_str("█   █ ");
                result[1].push_str("██  █ ");
                result[2].push_str("█ █ █ ");
                result[3].push_str("█ ██  ");
                result[4].push_str("█   █ ");
                result[5].push_str("█   █ ");
                result[6].push_str("     ");
            },
            'e' => {
                result[0].push_str("     ");
                result[1].push_str("     ");
                result[2].push_str(" ███ ");
                result[3].push_str("█  █ ");
                result[4].push_str("█  █ ");
                result[5].push_str(" ████");
                result[6].push_str("     ");
            },
            'x' => {
                result[0].push_str("     ");
                result[1].push_str("     ");
                result[2].push_str("█   █");
                result[3].push_str(" █ █ ");
                result[4].push_str("  █  ");
                result[5].push_str("█   █");
                result[6].push_str("     ");
            },
            'u' => {
                result[0].push_str("     ");
                result[1].push_str("     ");
                result[2].push_str("█   █");
                result[3].push_str("█   █");
                result[4].push_str("█   █");
                result[5].push_str(" ███ ");
                result[6].push_str("     ");
            },
            's' => {
                result[0].push_str("     ");
                result[1].push_str("     ");
                result[2].push_str(" ████");
                result[3].push_str("█    ");
                result[4].push_str(" ███ ");
                result[5].push_str("    █");
                result[6].push_str("████ ");
            },
            _ => {
                for i in 0..height {
                    result[i].push_str("  ");
                }
            }
        }
    }

    // 为了视觉效果，转换ASCII为彩色文本
    let mut colored_lines = Vec::new();
    for line in result {
        let mut colored_line = String::new();
        for c in line.chars() {
            if c == '█' {
                // 使用普通字符串，没有颜色
                colored_line.push(c);
            } else {
                // 使用普通字符串，没有颜色
                colored_line.push(c);
            }
        }
        colored_lines.push(colored_line);
    }
    
    colored_lines
}

/// 生成CLI欢迎横幅
pub fn generate_welcome_banner(environment: &Environment, version: &str) -> Vec<String> {
    vec![
        "".to_string(),
        "  Welcome to the".to_string(),
        "Nexus Network CLI".to_string(),
        version.to_string(),
        "".to_string(),
        "  Use the CLI to contribute to the massively-parallelized Nexus proof network."
            .to_string(),
        "".to_string(),
        "".to_string(),
        "Computational capacity of this node".to_string(),
        format!("{:.2} GFLOPS", measure_gflops()),
        "".to_string(),
        "Environment".to_string(),
        environment.to_string(),
        "".to_string(),
    ]
} 