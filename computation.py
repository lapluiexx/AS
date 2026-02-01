import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
import numpy as np
import matplotlib.gridspec as gridspec  # 引入 GridSpec 用于更灵活的布局
from matplotlib.colors import to_rgba

# --- 1. 数据准备 ---

data = {
    'Curve': [
        # 1. KeyGen (6 entries)
        'P-256', 'P-256', 'P-384', 'P-384', 'P-521', 'P-521',
        # 2. Sign (6 entries)
        'P-256', 'P-256', 'P-384', 'P-384', 'P-521', 'P-521',
        # 3. AS.SignAuth (6 entries)
        'P-256', 'P-256', 'P-384', 'P-384', 'P-521', 'P-521',
        # 4. Verify (6 entries)
        'P-256', 'P-256', 'P-384', 'P-384', 'P-521', 'P-521',
        # 5. AS.VerAuth (6 entries)
        'P-256', 'P-256', 'P-384', 'P-384', 'P-521', 'P-521',
    ],
    'Algorithm': [
        'KeyGen', 'KeyGen', 'KeyGen', 'KeyGen', 'KeyGen', 'KeyGen',
        'Sign', 'Sign', 'Sign', 'Sign', 'Sign', 'Sign',
        'AS.SignAuth', 'AS.SignAuth', 'AS.SignAuth', 'AS.SignAuth', 'AS.SignAuth',
        'AS.SignAuth',
        'Verify', 'Verify', 'Verify', 'Verify', 'Verify', 'Verify',
        'AS.VerAuth', 'AS.VerAuth', 'AS.VerAuth', 'AS.VerAuth', 'AS.VerAuth', 'AS.VerAuth',
    ],
    'Scheme': [
        'Basic ECDSA', 'AS-ECDSA', 'Basic ECDSA', 'AS-ECDSA', 'Basic ECDSA', 'AS-ECDSA',
        'Basic ECDSA', 'AS-ECDSA', 'Basic ECDSA', 'AS-ECDSA', 'Basic ECDSA', 'AS-ECDSA',
        'Basic ECDSA', 'AS-ECDSA', 'Basic ECDSA', 'AS-ECDSA', 'Basic ECDSA', 'AS-ECDSA',
        'Basic ECDSA', 'AS-ECDSA', 'Basic ECDSA', 'AS-ECDSA', 'Basic ECDSA', 'AS-ECDSA',
        'Basic ECDSA', 'AS-ECDSA', 'Basic ECDSA', 'AS-ECDSA', 'Basic ECDSA', 'AS-ECDSA',
    ],
    'Time': [
        

        # 1. KeyGen (Excel Row 1)
        6.608, 7.279, 15.659, 15.931, 31.496, 32.185,

        # 2. Sign (Excel Row 2)
        0.651, 0.797, 1.287, 1.562, 2.894, 2.622,

        # 3. AS.SignAuth (Excel Row 3)
        np.nan, 1.598, np.nan, 3.192, np.nan, 6.991,

        # 4. Verify (Excel Row 4)
        0.124, 0.146, 0.181, 0.163, 0.279, 0.303,

        # 5. AS.VerAuth (Excel Row 5)
        np.nan, 0.265, np.nan, 0.315, np.nan, 0.509,
    ]
}

df = pd.DataFrame(data)

# --- 2. 设置全局字体 ---
plt.rcParams['font.family'] = 'serif'
plt.rcParams['font.serif'] = ['Times New Roman']
plt.rcParams['axes.unicode_minus'] = False

# --- 3. 颜色与绘图顺序 ---
blue = to_rgba((169 / 255, 224 / 255, 247 / 255), alpha=1)
orange = to_rgba((252 / 255, 210 / 255, 138 / 255), alpha=1)
palette = [blue, orange]
plot_order = ['KeyGen', 'Sign', 'AS.SignAuth', 'Verify', 'AS.VerAuth']

# --- 4. 布局设置 (GridSpec) ---
# 创建画布
fig = plt.figure(figsize=(30, 18))

# 定义 2行 x 6列 的网格
gs = fig.add_gridspec(2, 6)

# 第一行：3个图，每图占2列 -> 填满 0-6 列
ax1 = fig.add_subplot(gs[0, 0:2])
ax2 = fig.add_subplot(gs[0, 2:4])
ax3 = fig.add_subplot(gs[0, 4:6])

# 第二行：2个图，居中
# 左边空出第0列，ax4 占 1-3列，ax5 占 3-5列，右边空出第6列
ax4 = fig.add_subplot(gs[1, 1:3])
ax5 = fig.add_subplot(gs[1, 3:5])

# 将 ax 放入列表，方便循环处理
axes = [ax1, ax2, ax3, ax4, ax5]
labels = ['(a)', '(b)', '(c)', '(d)', '(e)']

# --- 5. 循环绘图 ---
for i, algorithm in enumerate(plot_order):
    ax = axes[i]
    subset_df = df[df['Algorithm'] == algorithm]

    # [修改点] width=0.92 使柱子变宽 (最大建议 1.0)
    sns.barplot(
        data=subset_df,
        x="Curve",
        y="Time",
        hue="Scheme",
        palette=palette,
        width=0.92,
        ax=ax
    )

    # --- 美化 ---
    ax.set_xlabel("Elliptic Curves", fontsize=28)
    ax.set_ylabel("Execution Time (milliseconds)", fontsize=30)
    ax.tick_params(axis='both', which='major', labelsize=26)

    # 数值标注
    for p in ax.patches:
        height = p.get_height()
        if pd.notna(height) and height > 0:
            annotation_format = format(height, '.3f')

            ax.annotate(annotation_format,
                        (p.get_x() + p.get_width() / 2., height),
                        ha='center', va='center',
                        xytext=(0, 15),
                        textcoords='offset points',
                        fontsize=26)

    ax.patch.set_edgecolor('black')
    ax.patch.set_linewidth(1.5)
    ax.patch.set_linestyle('--')

    # Y轴范围设置
    if algorithm == "KeyGen":
        ax.set_ylim(0, 40)
    elif algorithm == "Sign":
        ax.set_ylim(0, 3.5)
    elif algorithm == "AS.SignAuth":
        ax.set_ylim(0, 8)
    elif algorithm == "Verify":
        ax.set_ylim(0, 0.6)
    elif algorithm == "AS.VerAuth":
        ax.set_ylim(0, 0.6)

    # 图例处理
    if i == 0:
        legend = ax.legend(loc='upper left', fontsize=22, frameon=True)
        plt.setp(legend.get_title(), fontsize=22)
    else:
        if ax.get_legend() is not None:
            ax.get_legend().remove()

    # 子图标签
    ax.text(0.5, -0.22, f"{labels[i]} Algorithm: {algorithm}", fontsize=30, weight='bold', ha='center', va='center',
            transform=ax.transAxes)

# --- 6. 最终显示 ---
# 调整间距，w_pad 控制左右间距，h_pad 控制上下间距
plt.tight_layout(rect=[0, 0.05, 1, 1], h_pad=5.0, w_pad=3.0)

plt.savefig("computation_centered.png", dpi=300, bbox_inches='tight')
plt.show()